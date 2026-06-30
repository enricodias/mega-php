<?php

declare(strict_types=1);

namespace Mega\Transport;

use Mega\Crypto\A32;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\FileMac;
use Mega\Crypto\NodeKey;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamInterface;

/**
 * Downloads and decrypts a MEGA file from a temporary download URL.
 *
 * Uses the caller-supplied PSR-18 HTTP client and PSR-17 request factory so
 * that the transport layer is fully swappable and testable without raw sockets.
 * The response body is read one MEGA chunk at a time via the PSR-7 stream so
 * that arbitrarily large files never need to be held in memory at once.
 */
class Downloader
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    public function __construct(ClientInterface $httpClient, RequestFactoryInterface $requestFactory)
    {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
    }

    /**
     * Fetch $url, decrypt each chunk as it arrives, and write plaintext into
     * $destination.
     *
     * @param string     $url         Temporary download URL returned by the MEGA API
     * @param int        $size        Total file size in bytes
     * @param array<int> $nodeKey     8-element a32 file node key
     * @param resource   $destination Writable stream resource
     *
     * @return int Total bytes written
     *
     * @throws CryptoException
     * @throws HttpException
     */
    public function download(string $url, int $size, array $nodeKey, $destination): int
    {
        $body = $this->openResponseStream($url);
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);
        $written = 0;
        $chunks = ChunkSizer::getChunks($size);
        $chunkMacs = [];

        foreach ($chunks as $chunkSize) {
            $cipherChunk = $this->readExactly($body, $chunkSize);

            $plain = \openssl_decrypt(
                $cipherChunk,
                'aes-128-ctr',
                $aesKey,
                \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
                $iv
            );

            if ($plain === false) {
                throw new CryptoException('AES-CTR decryption failed for chunk.');
            }

            $chunkMacs[] = FileMac::chunkMac($plain, $aesKey, $nodeKey);

            $iv = ChunkSizer::incrementIv($iv, $chunkSize);
            $written += $this->writeExactly($destination, $plain);
        }

        $this->verifyFileMac($chunkMacs, $aesKey, $nodeKey);

        return $written;
    }

    /**
     * Fetch $url, decrypt the content, and return it as a string.
     *
     * Intended for small files or when the caller has no writable stream at
     * hand. Internally uses a php://memory buffer to avoid allocating the
     * whole file twice.
     *
     * @param string     $url     Temporary download URL returned by the MEGA API
     * @param int        $size    Total file size in bytes
     * @param array<int> $nodeKey 8-element a32 file node key
     *
     * @return string Decrypted file contents
     *
     * @throws CryptoException
     * @throws HttpException
     */
    public function downloadToString(string $url, int $size, array $nodeKey): string
    {
        $memory = \fopen('php://memory', 'wb+');
        
        if ($memory === false) {
            throw new \RuntimeException('Failed to open in-memory stream.');
        }

        $this->download($url, $size, $nodeKey, $memory);

        \rewind($memory);
        $content = \stream_get_contents($memory);
        \fclose($memory);

        return $content === false ? '' : $content;
    }

    /**
     * @throws HttpException
     */
    private function openResponseStream(string $url): StreamInterface
    {
        $request = $this->requestFactory->createRequest('GET', $url);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new HttpException('Download request failed: ' . $e->getMessage(), 0, $e);
        }

        $status = $response->getStatusCode();

        if ($status < 200 || $status >= 300) {
            throw new HttpException('Download request returned HTTP status ' . $status . '.');
        }

        return $response->getBody();
    }

    /**
     * Read exactly $length bytes from a PSR-7 stream, accumulating across
     * multiple reads if the stream returns less than requested.
     */
    private function readExactly(StreamInterface $stream, int $length): string
    {
        $buffer = '';

        while (\strlen($buffer) < $length && !$stream->eof()) {
            $chunk = $stream->read($length - \strlen($buffer));
            if ($chunk === '') {
                break;
            }
            $buffer .= $chunk;
        }

        if (\strlen($buffer) < $length) {
            throw new HttpException('Download response ended before expected content length was reached.');
        }

        return $buffer;
    }

    /**
     * Write $data to $destination, looping until every byte is written.
     *
     * @throws HttpException
     */
    private function writeExactly($destination, string $data): int
    {
        $length = \strlen($data);
        $written = 0;

        while ($written < $length) {
            $bytes = \fwrite($destination, \substr($data, $written));

            if ($bytes === false || $bytes === 0) {
                throw new HttpException('Failed to write decrypted chunk to destination stream.');
            }

            $written += $bytes;
        }

        return $written;
    }

    /**
     * Compare the accumulated chunk MACs against the file MAC embedded in
     * the node key (words 6 and 7).
     *
     * @param array<array<int>> $chunkMacs
     * @param array<int>        $nodeKey
     *
     * @throws CryptoException
     */
    private function verifyFileMac(array $chunkMacs, string $aesKey, array $nodeKey): void
    {
        $fileMac = FileMac::fileMac($chunkMacs, $aesKey);
        $expected = [$nodeKey[6], $nodeKey[7]];
        $actual = [$fileMac[0], $fileMac[1]];

        if ($actual !== $expected) {
            throw new CryptoException('Downloaded file failed MAC verification; content may be corrupted or tampered with.');
        }
    }
}
