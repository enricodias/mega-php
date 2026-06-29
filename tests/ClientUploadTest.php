<?php

declare(strict_types=1);

namespace Mega\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Client;
use Mega\Config;
use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\NodeKey;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Entity\TransferResult;
use Mega\Exception\AuthException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientUploadTest extends TestCase
{
    public function testUploadFileRequiresSession(): void
    {
        $stream = \fopen('php://memory', 'rb+');
        $client = $this->makeClientWithMockedUploader('[]', $this->createMock(Uploader::class));

        $this->expectException(AuthException::class);

        $client->uploadFile($stream, 'parentHd');
    }

    public function testUploadFileSendsUploadSizeCommand(): void
    {
        $plaintext = \str_repeat('A', 16);
        $stream = $this->makeStream($plaintext);

        $uploader = $this->createMock(Uploader::class);
        $uploader->method('upload')->willReturn('completion-token');

        $apiRequests = [];
        $nodeCreateResponse = \json_encode([
            ['f' => [['h' => 'newHndl1', 't' => Node::TYPE_FILE, 'k' => '', 'a' => '']]],
        ]);
        $uploadUrlResponse = \json_encode([['p' => 'https://upload.example.invalid/']]);

        $client = $this->makeClientCapturingTwoApiRequests(
            $uploadUrlResponse,
            $nodeCreateResponse,
            $apiRequests,
            $uploader
        );
        $client->restoreSession($this->session());

        $client->uploadFile($stream, 'parentHd', 'test.bin');

        $this->assertCount(2, $apiRequests);

        $firstBody = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $firstBody[0];

        $this->assertSame('u', $command['a']);
        $this->assertSame(\strlen($plaintext), $command['s']);
    }

    public function testUploadFileSendsNodeCreateCommand(): void
    {
        $plaintext = \str_repeat('B', 16);
        $stream = $this->makeStream($plaintext);

        $uploader = $this->createMock(Uploader::class);
        $uploader->method('upload')->willReturn('my-completion-token');

        $apiRequests = [];
        $nodeCreateResponse = \json_encode([
            ['f' => [['h' => 'newHndl2', 't' => Node::TYPE_FILE, 'k' => '', 'a' => '']]],
        ]);
        $uploadUrlResponse = \json_encode([['p' => 'https://upload.example.invalid/']]);

        $client = $this->makeClientCapturingTwoApiRequests(
            $uploadUrlResponse,
            $nodeCreateResponse,
            $apiRequests,
            $uploader
        );
        $client->restoreSession($this->session());

        $client->uploadFile($stream, 'parentHd', 'myfile.txt');

        $this->assertCount(2, $apiRequests);

        $secondBody = \json_decode((string) $apiRequests[1]->getBody(), true);
        $command = $secondBody[0];

        $this->assertSame('p', $command['a']);
        $this->assertSame('parentHd', $command['t']);
        $this->assertArrayHasKey('n', $command);
        $this->assertCount(1, $command['n']);

        $nodeEntry = $command['n'][0];
        $this->assertSame('my-completion-token', $nodeEntry['h']);
        $this->assertSame(Node::TYPE_FILE, $nodeEntry['t']);
        $this->assertArrayHasKey('a', $nodeEntry);
        $this->assertArrayHasKey('k', $nodeEntry);
    }

    public function testUploadFileNodeCreateContainsDecryptableAttributes(): void
    {
        $plaintext = \str_repeat('C', 16);
        $stream = $this->makeStream($plaintext);

        $uploader = $this->createMock(Uploader::class);
        $uploader->method('upload')->willReturn('tok');

        $apiRequests = [];
        $nodeCreateResponse = \json_encode([
            ['f' => [['h' => 'decAttrH', 't' => Node::TYPE_FILE, 'k' => '', 'a' => '']]],
        ]);
        $uploadUrlResponse = \json_encode([['p' => 'https://upload.example.invalid/']]);

        $client = $this->makeClientCapturingTwoApiRequests(
            $uploadUrlResponse,
            $nodeCreateResponse,
            $apiRequests,
            $uploader
        );
        $client->restoreSession($this->session());

        $client->uploadFile($stream, 'parentHd', 'secret.pdf');

        $secondBody = \json_decode((string) $apiRequests[1]->getBody(), true);
        $nodeEntry = $secondBody[0]['n'][0];

        $masterKeyStr = A32::toString($this->masterKey());
        $encKeyA32 = A32::fromBase64($nodeEntry['k']);
        $nodeKey = Aes::decryptKey($masterKeyStr, $encKeyA32);

        $attrCiphertext = Base64Url::decode($nodeEntry['a']);
        $attrs = Attr::decrypt($attrCiphertext, $nodeKey);

        $this->assertSame('secret.pdf', $attrs['n']);
    }

    public function testUploadFileReturnsTransferResultWithNodeHandle(): void
    {
        $plaintext = \str_repeat('D', 16);
        $stream = $this->makeStream($plaintext);

        $uploader = $this->createMock(Uploader::class);
        $uploader->method('upload')->willReturn('tok');

        $ignored = [];
        $nodeCreateResponse = \json_encode([
            ['f' => [['h' => 'returnedH', 't' => Node::TYPE_FILE, 'k' => '', 'a' => '']]],
        ]);
        $uploadUrlResponse = \json_encode([['p' => 'https://upload.example.invalid/']]);

        $client = $this->makeClientCapturingTwoApiRequests(
            $uploadUrlResponse,
            $nodeCreateResponse,
            $ignored,
            $uploader
        );
        $client->restoreSession($this->session());

        $result = $client->uploadFile($stream, 'parentHd', 'file.bin');

        $this->assertInstanceOf(TransferResult::class, $result);
        $this->assertSame('returnedH', $result->getNode()->getHandle());
        $this->assertSame(Node::TYPE_FILE, $result->getNode()->getType());
        $this->assertSame('file.bin', $result->getNode()->getName());
    }

    public function testUploadFileUsesBasenameFromPathWhenNameOmitted(): void
    {
        $tmpFile = \tempnam(\sys_get_temp_dir(), 'mega_test_');
        \file_put_contents((string) $tmpFile, 'hello');

        $uploader = $this->createMock(Uploader::class);
        $uploader->method('upload')->willReturn('tok');

        $apiRequests = [];
        $nodeCreateResponse = \json_encode([
            ['f' => [['h' => 'basenHndl', 't' => Node::TYPE_FILE, 'k' => '', 'a' => '']]],
        ]);
        $uploadUrlResponse = \json_encode([['p' => 'https://upload.example.invalid/']]);

        $client = $this->makeClientCapturingTwoApiRequests(
            $uploadUrlResponse,
            $nodeCreateResponse,
            $apiRequests,
            $uploader
        );
        $client->restoreSession($this->session());

        $client->uploadFile((string) $tmpFile);

        \unlink((string) $tmpFile);

        $secondBody = \json_decode((string) $apiRequests[1]->getBody(), true);
        $nodeEntry = $secondBody[0]['n'][0];

        $masterKeyStr = A32::toString($this->masterKey());
        $encKeyA32 = A32::fromBase64($nodeEntry['k']);
        $nodeKey = Aes::decryptKey($masterKeyStr, $encKeyA32);
        $attrCiphertext = Base64Url::decode($nodeEntry['a']);
        $attrs = Attr::decrypt($attrCiphertext, $nodeKey);

        $this->assertSame(\basename((string) $tmpFile), $attrs['n']);
    }

    public function testUploaderEncryptsChunkCorrectly(): void
    {
        $factory = new HttpFactory();

        $plaintext = \str_repeat('T', 16);
        $nodeKey = $this->fixedNodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = \Mega\Crypto\ChunkSizer::ivFromNodeKey($nodeKey);

        $expectedCipher = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $capturedPuts = [];
        $putMock = new MockHandler([new Response(200, [], 'completion-token')]);
        $putStack = HandlerStack::create($putMock);
        $putStack->push(function (callable $handler) use (&$capturedPuts) {
            return function ($request, array $options) use ($handler, &$capturedPuts) {
                $capturedPuts[] = $request;
                return $handler($request, $options);
            };
        });
        $putClient = new GuzzleClient(['handler' => $putStack]);

        $uploader = new Uploader($putClient, $factory, $factory);

        $stream = $this->makeStream($plaintext);
        $nodeKeyCopy = $nodeKey;
        $uploader->upload('https://upload.example.invalid', $stream, \strlen($plaintext), $nodeKeyCopy);

        $this->assertCount(1, $capturedPuts);

        $putBody = (string) $capturedPuts[0]->getBody();

        $this->assertSame($expectedCipher, $putBody);
    }

    public function testUploaderWritesFileMacIntoNodeKey(): void
    {
        $factory = new HttpFactory();

        $plaintext = \str_repeat('T', 16);
        $nodeKey = $this->fixedNodeKey();
        
        $putMock = new MockHandler([new Response(200, [], 'completion-token')]);
        $putStack = HandlerStack::create($putMock);
        $putStack->push(function (callable $handler) use (&$capturedPuts) {
            return function ($request, array $options) use ($handler, &$capturedPuts) {
                $capturedPuts[] = $request;
                return $handler($request, $options);
            };
        });
        $putClient = new GuzzleClient(['handler' => $putStack]);

        $uploader = new Uploader($putClient, $factory, $factory);

        $stream = $this->makeStream($plaintext);
        $nodeKeyCopy = $nodeKey;
        $uploader->upload('https://upload.example.invalid', $stream, \strlen($plaintext), $nodeKeyCopy);

        // computed manually
        $expected = [
            16909060,
            84281096,
            1574991273,
            3521221330,
            286397204,
            353769240,
            1424653989,
            3706691010,
        ];

        $this->assertSame($expected, $nodeKeyCopy);
    }

    /**
     * 4-element a32 master key shared across client-level upload tests.
     *
     * @return array<int>
     */
    private function masterKey(): array
    {
        return [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
    }

    /**
     * Fixed 8-element a32 node key used in Uploader unit tests.
     *
     * @return array<int>
     */
    private function fixedNodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    private function session(): Session
    {
        return new Session($this->masterKey(), 'test-session-id', []);
    }

    /**
     * @return resource
     */
    private function makeStream(string $content)
    {
        $stream = \fopen('php://memory', 'rb+');
        \fwrite($stream, $content);
        \rewind($stream);
        return $stream;
    }

    private function makeClientWithMockedUploader(string $apiResponseBody, Uploader $uploader): Client
    {
        $factory = new HttpFactory();

        $apiMock = new MockHandler([new Response(200, [], $apiResponseBody)]);
        $apiStack = HandlerStack::create($apiMock);
        $apiHttpClient = new GuzzleClient(['handler' => $apiStack]);

        $connector = new Connector(
            Config::SERVER_GLOBAL,
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $downloader = $this->createMock(Downloader::class);

        return new Client($connector, $downloader, $uploader, new NullLogger());
    }

    /**
     * Builds a Client whose Connector returns two sequential API responses:
     * the first for the upload-URL command, the second for node-create.
     *
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeClientCapturingTwoApiRequests(
        string $firstApiResponse,
        string $secondApiResponse,
        array &$capturedApiRequests,
        Uploader $uploader
    ): Client {
        $factory = new HttpFactory();

        $apiMock = new MockHandler([
            new Response(200, [], $firstApiResponse),
            new Response(200, [], $secondApiResponse),
        ]);
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

        $downloader = $this->createMock(Downloader::class);

        return new Client($connector, $downloader, $uploader, new NullLogger());
    }
}
