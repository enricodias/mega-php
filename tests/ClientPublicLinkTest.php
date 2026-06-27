<?php

declare(strict_types=1);

namespace Mega\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Client;
use Mega\Crypto\A32;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\NodeKey;
use Mega\Entity\FileInfo;
use Mega\Exception\InvalidLinkException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientPublicLinkTest extends TestCase
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

    public function testGetPublicFileInfoReturnsFileInfo(): void
    {
        $encodedAttr = $this->encodedAttr('hello.txt');
        $apiResponse = \json_encode([['s' => 1234, 'at' => $encodedAttr]]);
        $link = 'https://mega.nz/file/AbCdEfGh#' . $this->linkKey();

        $client = $this->makeClient((string) $apiResponse);
        $info = $client->getPublicFileInfo($link);

        $this->assertInstanceOf(FileInfo::class, $info);
        $this->assertSame('hello.txt', $info->getName());
        $this->assertSame(1234, $info->getSize());
        $this->assertNull($info->getDownloadUrl());
    }

    public function testGetPublicFileInfoSendsCorrectCommand(): void
    {
        $encodedAttr = $this->encodedAttr('test.bin');
        $apiResponse = \json_encode([['s' => 99, 'at' => $encodedAttr]]);
        $link = 'https://mega.nz/file/MyHandleX#' . $this->linkKey();

        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $apiRequests);
        $client->getPublicFileInfo($link);

        $this->assertCount(1, $apiRequests);
        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('g', $command['a']);
        $this->assertSame('MyHandleX', $command['p']);
        $this->assertSame(0, $command['g']);
    }

    public function testGetPublicFileInfoThrowsOnInvalidLink(): void
    {
        $client = $this->makeClient('[]');

        $this->expectException(InvalidLinkException::class);

        $client->getPublicFileInfo('https://not-a-mega-link.example.com/');
    }

    public function testDownloadPublicFileSendsRequestWithDlFlag(): void
    {
        $plaintext = \str_repeat('A', 16);
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);
        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $encodedAttr = $this->encodedAttr('download.txt');
        $apiResponse = \json_encode([[
            's'  => \strlen($plaintext),
            'at' => $encodedAttr,
            'g'  => 'https://example.invalid/dl',
        ]]);

        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests(
            (string) $apiResponse,
            $apiRequests,
            $ciphertext
        );

        $dest = \fopen('php://memory', 'wb+');
        $client->downloadPublicFile('https://mega.nz/file/AbCdEfGh#' . $this->linkKey(), $dest);

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];
        $this->assertSame('g', $command['a']);
        $this->assertSame(1, $command['g']);

        \rewind($dest);
        $this->assertSame($plaintext, \stream_get_contents($dest));
        \fclose($dest);
    }

    public function testDownloadPublicFileReturnsStringWhenNoDestination(): void
    {
        $plaintext = \str_repeat('B', 16);
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);
        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $encodedAttr = $this->encodedAttr('string.txt');
        $apiResponse = \json_encode([[
            's'  => \strlen($plaintext),
            'at' => $encodedAttr,
            'g'  => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $client  = $this->makeClientCapturingApiRequests(
            (string) $apiResponse,
            $ignored,
            $ciphertext
        );

        $result = $client->downloadPublicFile('https://mega.nz/file/AbCdEfGh#' . $this->linkKey());

        $this->assertSame($plaintext, $result);
    }

    private function makeClient(string $apiResponseBody): Client
    {
        $ignored = [];
        return $this->makeClientCapturingApiRequests($apiResponseBody, $ignored);
    }

    /**
     * Builds a Client with two separate Guzzle mock stacks:
     * - One for the Connector (JSON API calls), returning $apiResponseBody.
     * - One for the Downloader (file GET), returning $downloadBody when provided.
     *
     * Requests sent to the Connector stack are captured into $capturedApiRequests.
     *
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeClientCapturingApiRequests(
        string $apiResponseBody,
        array &$capturedApiRequests,
        string $downloadBody = ''
    ): Client {
        $factory = new HttpFactory();

        // Connector stack: captures requests and returns the API response
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
            'https://g.api.mega.co.nz/',
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        // Downloader stack: returns the raw (encrypted) file body
        $dlMock  = new MockHandler([new Response(200, [], $downloadBody)]);
        $dlStack = HandlerStack::create($dlMock);
        $dlHttpClient = new GuzzleClient(['handler' => $dlStack]);

        $downloader = new Downloader($dlHttpClient, $factory);

        return new Client($connector, $downloader, new NullLogger());
    }
}
