<?php

declare(strict_types=1);

namespace Mega\Transport;

use Mega\Crypto\A32;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\FileMac;
use Mega\Crypto\NodeKey;
use Mega\Exception\ApiException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Encrypts and uploads a file to a MEGA upload URL.
 *
 * Chunks are encrypted one at a time with AES-128-CTR and PUT sequentially.
 * The final PUT returns a completion token that must be submitted in the
 * node-create command. The file MAC is computed over the plaintext and
 * written back into the node key so the caller can include it in the
 * encrypted node key submitted to the API.
 */
class Uploader
{
    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    public function __construct(
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory
    ) {
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
    }

    /**
     * Encrypt and upload all chunks from $source to $uploadUrl.
     *
     * Reads from $source one chunk at a time, encrypts with AES-128-CTR,
     * and PUTs each chunk to the upload URL with its byte offset appended.
     * Returns the completion token from the final chunk's response.
     *
     * The $nodeKey array is modified in place to embed the computed file MAC.
     * The full 8-element node key layout is:
     *   [aes0^iv0, aes1^iv1, aes2^mac0, aes3^mac1, iv0, iv1, mac0, mac1]
     * Words 2, 3, 6 and 7 are updated once the file MAC is known.
     *
     * @param string     $uploadUrl Temporary upload URL from the 'u' command
     * @param resource   $source    Readable stream positioned at offset 0
     * @param int        $size      Total byte length of the source stream
     * @param array<int> $nodeKey   8-element a32 node key (modified in place)
     *
     * @return string Completion token returned by the upload server
     *
     * @throws CryptoException
     * @throws HttpException
     * @throws ApiException
     */
    public function upload(string $uploadUrl, $source, int $size, array &$nodeKey): string
    {
        if ($size === 0) {
            throw new CryptoException('Cannot upload an empty file.');
        }

        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);
        $chunks = ChunkSizer::getChunks($size);

        $chunkMacs = [];
        $completionToken = '';

        foreach ($chunks as $offset => $chunkSize) {
            $plainChunk = $this->readExactly($source, $chunkSize);

            if (\strlen($plainChunk) < $chunkSize) {
                throw new CryptoException(
                    'Unexpected EOF reading chunk at offset ' . $offset . ': '
                    . 'expected ' . $chunkSize . ' bytes, got ' . \strlen($plainChunk) . '.'
                );
            }

            $cipherChunk = \openssl_encrypt(
                $plainChunk,
                'aes-128-ctr',
                $aesKey,
                \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
                $iv
            );

            if ($cipherChunk === false) {
                throw new CryptoException('AES-CTR encryption failed for chunk at offset ' . $offset . '.');
            }

            $chunkMacs[] = FileMac::chunkMac($plainChunk, $aesKey, $nodeKey);

            $iv = ChunkSizer::incrementIv($iv, $chunkSize);

            $completionToken = $this->putChunk($uploadUrl, $offset, $cipherChunk);
        }

        $fileMac = FileMac::fileMac($chunkMacs, $aesKey);

        // Embed mac into word positions 2, 3, 6, 7 of the node key.
        // Words 2 and 3 started as aes2^0 and aes3^0; XOR with mac finalises them.
        $nodeKey[2] ^= $fileMac[0];
        $nodeKey[3] ^= $fileMac[1];
        $nodeKey[6] = $fileMac[0];
        $nodeKey[7] = $fileMac[1];

        return $completionToken;
    }

    /**
     * Read exactly $length bytes from a PHP stream resource, accumulating
     * across multiple reads if the stream returns fewer bytes than requested.
     *
     * @param resource $source
     */
    private function readExactly($source, int $length): string
    {
        $buffer = '';

        while (\strlen($buffer) < $length) {
            $chunk = \fread($source, $length - \strlen($buffer));

            if ($chunk === false || $chunk === '') {
                break;
            }

            $buffer .= $chunk;
        }

        return $buffer;
    }

    /**
     * PUT a single encrypted chunk to the upload server.
     *
     * @throws HttpException
     * @throws ApiException
     */
    private function putChunk(string $uploadUrl, int $offset, string $cipherChunk): string
    {
        $url = \rtrim($uploadUrl, '/') . '/' . $offset;

        $stream = $this->streamFactory->createStream($cipherChunk);

        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/octet-stream')
            ->withHeader('Content-Length', (string) \strlen($cipherChunk))
            ->withBody($stream);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new HttpException('Upload chunk request failed: ' . $e->getMessage(), 0, $e);
        }

        $statusCode = $response->getStatusCode();
        if ($statusCode < 200 || $statusCode >= 300) {
            throw new HttpException(
                'Upload chunk request returned HTTP ' . $statusCode . ' at offset ' . $offset . '.'
            );
        }

        $body = (string) $response->getBody();

        // The MEGA upload server returns a negative integer on error
        if ($body !== '' && \is_numeric(\trim($body))) {
            $code = (int) \trim($body);

            if ($code < 0) {
                throw ApiException::fromCode($code);
            }
        }

        return $body;
    }
}
