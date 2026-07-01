<?php

declare(strict_types=1);

namespace Mega\Tests\Service;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Config;
use Mega\Crypto\A32;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\FileMac;
use Mega\Crypto\NodeKey;
use Mega\Entity\FileInfo;
use Mega\Exception\ApiException;
use Mega\Exception\InvalidLinkException;
use Mega\Service\PublicFileService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class PublicFileServiceTest extends TestCase
{
    /**
     * 8-element a32 file node key used as the "key" component in links.
     *
     * @return array<int>
     */
    private function nodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    /**
     * Build a MEGA-format link key (base64url of the raw 32-byte node key).
     */
    private function linkKey(): string
    {
        return A32::toBase64($this->nodeKey());
    }

    /**
     * Encrypt attributes using Attr::encrypt and return base64url-encoded ciphertext
     * as MEGA returns in the "at" API field.
     */
    private function encodedAttr(string $filename): string
    {
        $ciphertext = Attr::encrypt(['n' => $filename], $this->nodeKey());

        return Base64Url::encode($ciphertext);
    }

    public function testGetFileInfoReturnsFileInfo(): void
    {
        $encodedAttr = $this->encodedAttr('hello.txt');
        $apiResponse = \json_encode([['s' => 1234, 'at' => $encodedAttr]]);
        $link = 'https://mega.nz/file/AbCdEfGh#' . $this->linkKey();

        $service = $this->makeService((string) $apiResponse);
        $info = $service->getFileInfo($link);

        $this->assertInstanceOf(FileInfo::class, $info);
        $this->assertSame('hello.txt', $info->getName());
        $this->assertSame(1234, $info->getSize());
        $this->assertNull($info->getDownloadUrl());
    }

    public function testGetFileInfoSendsCorrectCommand(): void
    {
        $encodedAttr = $this->encodedAttr('test.bin');
        $apiResponse = \json_encode([['s' => 99, 'at' => $encodedAttr]]);
        $link = 'https://mega.nz/file/MyHandleX#' . $this->linkKey();

        $apiRequests = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $apiRequests);
        $service->getFileInfo($link);

        $this->assertCount(1, $apiRequests);
        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('g', $command['a']);
        $this->assertSame('MyHandleX', $command['p']);
        $this->assertSame(0, $command['g']);
    }

    public function testGetFileInfoThrowsOnInvalidLink(): void
    {
        $service = $this->makeService('[]');

        $this->expectException(InvalidLinkException::class);

        $service->getFileInfo('https://not-a-mega-link.example.com/');
    }

    public function testGetFileInfoThrowsOnFolderLink(): void
    {
        $service = $this->makeService('[]');

        $this->expectException(InvalidLinkException::class);

        $service->getFileInfo('https://mega.nz/folder/FolderHnd#' . $this->linkKey());
    }

    public function testGetFileInfoThrowsOnShortKey(): void
    {
        $service = $this->makeService('[]');
        $shortKey = A32::toBase64([0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10]);

        $this->expectException(InvalidLinkException::class);

        $service->getFileInfo('https://mega.nz/file/AbCdEfGh#' . $shortKey);
    }

    public function testGetFileInfoThrowsOnMissingSize(): void
    {
        $encodedAttr = $this->encodedAttr('hello.txt');
        $apiResponse = \json_encode([['at' => $encodedAttr]]);
        $link = 'https://mega.nz/file/AbCdEfGh#' . $this->linkKey();

        $service = $this->makeService((string) $apiResponse);

        $this->expectException(ApiException::class);

        $service->getFileInfo($link);
    }

    public function testDownloadThrowsOnFolderLink(): void
    {
        $service = $this->makeService('[]');

        $this->expectException(InvalidLinkException::class);

        $service->download('https://mega.nz/folder/FolderHnd#' . $this->linkKey());
    }

    public function testDownloadSendsRequestWithDlFlag(): void
    {
        $plaintext = \str_repeat('A', 16);
        $fixture = $this->buildFileFixture($plaintext);

        $encodedAttr = $this->encodedAttr('download.txt');
        $linkKey = A32::toBase64($fixture['nodeKey']);
        $apiResponse = \json_encode([[
            's'  => \strlen($plaintext),
            'at' => $encodedAttr,
            'g'  => 'https://example.invalid/dl',
        ]]);

        $apiRequests = [];
        $service = $this->makeServiceCapturingApiRequests(
            (string) $apiResponse,
            $apiRequests,
            $fixture['ciphertext']
        );

        $dest = \fopen('php://memory', 'wb+');
        $service->download('https://mega.nz/file/AbCdEfGh#' . $linkKey, $dest);

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];
        $this->assertSame('g', $command['a']);
        $this->assertSame(1, $command['g']);

        \rewind($dest);
        $this->assertSame($plaintext, \stream_get_contents($dest));
        \fclose($dest);
    }

    public function testDownloadReturnsStringWhenNoDestination(): void
    {
        $plaintext = \str_repeat('B', 16);
        $fixture = $this->buildFileFixture($plaintext);

        $encodedAttr = $this->encodedAttr('string.txt');
        $linkKey = A32::toBase64($fixture['nodeKey']);
        $apiResponse = \json_encode([[
            's'  => \strlen($plaintext),
            'at' => $encodedAttr,
            'g'  => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $service = $this->makeServiceCapturingApiRequests(
            (string) $apiResponse,
            $ignored,
            $fixture['ciphertext']
        );

        $result = $service->download('https://mega.nz/file/AbCdEfGh#' . $linkKey);

        $this->assertSame($plaintext, $result);
    }

    /**
     * Build a self-consistent (ciphertext, complete nodeKey) fixture using
     * words 6/7 = 0 for AES key derivation, then embed the computed file MAC
     * into words 2, 3, 6, 7, matching the Uploader::upload() flow.
     *
     * @return array{nodeKey: array<int>, ciphertext: string}
     */
    private function buildFileFixture(string $plaintext): array
    {
        $nodeKey = [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                    0x11121314, 0x15161718, 0x00000000, 0x00000000];

        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);

        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $chunkMac = FileMac::chunkMac($plaintext, $aesKey, $nodeKey);
        $fileMac  = FileMac::fileMac([$chunkMac], $aesKey);

        $nodeKey[2] ^= $fileMac[0];
        $nodeKey[3] ^= $fileMac[1];
        $nodeKey[6]  = $fileMac[0];
        $nodeKey[7]  = $fileMac[1];

        return ['nodeKey' => $nodeKey, 'ciphertext' => $ciphertext];
    }

    private function makeService(string $apiResponseBody): PublicFileService
    {
        $ignored = [];
        return $this->makeServiceCapturingApiRequests($apiResponseBody, $ignored);
    }

    /**
     * Builds a PublicFileService with two separate Guzzle mock stacks:
     * - One for the Connector (JSON API calls), returning $apiResponseBody.
     * - One for the Downloader (file GET), returning $downloadBody when provided.
     *
     * Requests sent to the Connector stack are captured into $capturedApiRequests.
     *
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeServiceCapturingApiRequests(
        string $apiResponseBody,
        array &$capturedApiRequests,
        string $downloadBody = ''
    ): PublicFileService {
        $factory = new HttpFactory();

        $apiMock = new MockHandler([new Response(200, [], $apiResponseBody)]);
        $apiStack = HandlerStack::create($apiMock);
        $apiStack->push(function (callable $handler) use (&$capturedApiRequests) {
            return function ($request, array $options) use ($handler, &$capturedApiRequests) {
                $capturedApiRequests[] = $request;
                return $handler($request, $options);
            };
        });
        $apiHttpClient = new GuzzleClient(['handler' => $apiStack]);

        $connector = new Connector(
            Config::SERVER_GLOBAL,
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $dlMock = new MockHandler([new Response(200, [], $downloadBody)]);
        $dlStack = HandlerStack::create($dlMock);
        $dlHttpClient = new GuzzleClient(['handler' => $dlStack]);

        $downloader = new Downloader($dlHttpClient, $factory);

        return new PublicFileService($connector, $downloader);
    }
}
