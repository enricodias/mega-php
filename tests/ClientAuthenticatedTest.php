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
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\NodeKey;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Exception\AuthException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientAuthenticatedTest extends TestCase
{
    public function testListNodesRequiresSession(): void
    {
        $client = $this->makeClientCapturingApiRequests('[]');

        $this->expectException(AuthException::class);

        $client->listNodes();
    }

    public function testListNodesReturnsEmptyArrayWhenResponseHasNoFKey(): void
    {
        $apiResponse = \json_encode([[/* no 'f' key */]]);
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertSame([], $nodes);
    }

    public function testListNodesSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $apiResponse = \json_encode([['f' => []]]);
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $apiRequests);
        $client->restoreSession($this->session());

        $client->listNodes();

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];
        
        $this->assertSame('f', $command['a']);
        $this->assertSame(1, $command['c']);
    }

    public function testListNodesDecryptsFileAndFolderNodes(): void
    {
        $fileKey = $this->fileNodeKey();
        $folderKey = $this->folderNodeKey();

        $rawNodes = [
            [
                'h' => 'fileHndl',
                't' => Node::TYPE_FILE,
                'k' => $this->encryptedRawKey($fileKey),
                'a' => $this->encodedAttr('document.txt', $fileKey),
            ],
            [
                'h' => 'foldHndl',
                't' => Node::TYPE_FOLDER,
                'k' => $this->encryptedRawKey($folderKey),
                'a' => $this->encodedAttr('My Folder', $folderKey),
            ],
        ];

        $apiResponse = \json_encode([['f' => $rawNodes]]);
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertCount(2, $nodes);

        $this->assertSame('fileHndl', $nodes[0]->getHandle());
        $this->assertSame(Node::TYPE_FILE, $nodes[0]->getType());
        $this->assertSame('document.txt', $nodes[0]->getName());

        $this->assertSame('foldHndl', $nodes[1]->getHandle());
        $this->assertSame(Node::TYPE_FOLDER, $nodes[1]->getType());
        $this->assertSame('My Folder', $nodes[1]->getName());
    }

    public function testListNodesSkipsNonFileNonFolderTypes(): void
    {
        $rawNodes = [
            ['h' => 'rootHndl', 't' => 2, 'k' => '', 'a' => ''],
            ['h' => 'inbxHndl', 't' => 3, 'k' => '', 'a' => ''],
            ['h' => 'trshHndl', 't' => 4, 'k' => '', 'a' => ''],
        ];

        $apiResponse = \json_encode([['f' => $rawNodes]]);
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertSame([], $nodes);
    }

    public function testListNodesSkipsNodesWithUndecryptableKeys(): void
    {
        $fileKey = $this->fileNodeKey();

        $rawNodes = [
            [
                'h' => 'goodHndl',
                't' => Node::TYPE_FILE,
                'k' => $this->encryptedRawKey($fileKey),
                'a' => $this->encodedAttr('good.txt', $fileKey),
            ],
            [
                // Missing ':' separator means the key portion will be empty,
                // causing decryptNodeKey to throw CryptoException.
                'h' => 'badHHndl',
                't' => Node::TYPE_FILE,
                'k' => 'no-colon-separator',
                'a' => '',
            ],
        ];

        $apiResponse = \json_encode([['f' => $rawNodes]]);
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertCount(1, $nodes);
        $this->assertSame('goodHndl', $nodes[0]->getHandle());
    }

    public function testGetFileInfoRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');
        $client = $this->makeClientCapturingApiRequests('[]');

        $this->expectException(AuthException::class);

        $client->getFileInfo($node);
    }

    public function testGetFileInfoSendsCorrectCommand(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', $rawKey);

        $encodedAttr = $this->encodedAttr('file.txt', $fileKey);
        $apiResponse = \json_encode([['s' => 512, 'at' => $encodedAttr]]);

        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $apiRequests);
        $client->restoreSession($this->session());

        $client->getFileInfo($node);

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('g', $command['a']);
        $this->assertSame('myFileHd', $command['n']);
        $this->assertSame(0, $command['g']);
    }

    public function testGetFileInfoReturnsDecryptedFileInfo(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', $rawKey);

        $encodedAttr = $this->encodedAttr('report.pdf', $fileKey);
        $apiResponse = \json_encode([['s' => 2048, 'at' => $encodedAttr]]);

        $client = $this->makeClientCapturingApiRequests((string) $apiResponse);
        $client->restoreSession($this->session());

        $info = $client->getFileInfo($node);

        $this->assertSame('report.pdf', $info->getName());
        $this->assertSame(2048, $info->getSize());
        $this->assertNull($info->getDownloadUrl());
    }

    public function testDownloadFileRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');
        $client = $this->makeClientCapturingApiRequests('[]');

        $this->expectException(AuthException::class);

        $client->downloadFile($node);
    }

    public function testDownloadFileSendsCorrectCommand(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $plaintext = \str_repeat('X', 16);
        $aesKey = A32::toString(NodeKey::foldToAesKey($fileKey));
        $iv = ChunkSizer::ivFromNodeKey($fileKey);
        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $apiRequests, $ciphertext);
        $client->restoreSession($this->session());

        $client->downloadFile($node);

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('g', $command['a']);
        $this->assertSame('dlFileHd', $command['n']);
        $this->assertSame(1, $command['g']);
    }

    public function testDownloadFileReturnsDecryptedContent(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $plaintext = \str_repeat('Y', 16);
        $aesKey = A32::toString(NodeKey::foldToAesKey($fileKey));
        $iv = ChunkSizer::ivFromNodeKey($fileKey);
        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $ignored, $ciphertext);
        $client->restoreSession($this->session());

        $result = $client->downloadFile($node);

        $this->assertSame($plaintext, $result);
    }

    public function testDownloadFileWritesToDestinationStream(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $plaintext = \str_repeat('Z', 16);
        $aesKey = A32::toString(NodeKey::foldToAesKey($fileKey));
        $iv = ChunkSizer::ivFromNodeKey($fileKey);
        $ciphertext = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $client = $this->makeClientCapturingApiRequests((string) $apiResponse, $ignored, $ciphertext);
        $client->restoreSession($this->session());

        $dest = \fopen('php://memory', 'wb+');
        $bytesWritten = $client->downloadFile($node, $dest);

        \rewind($dest);
        $this->assertSame($plaintext, \stream_get_contents($dest));
        $this->assertSame(\strlen($plaintext), $bytesWritten);
        \fclose($dest);
    }

    /**
     * 4-element a32 master key used for all tests.
     *
     * @return array<int>
     */
    private function masterKey(): array
    {
        return [0xDEADBEEF, 0xCAFEBABE, 0x12345678, 0x9ABCDEF0];
    }

    /**
     * 8-element a32 file node key (plaintext).
     *
     * @return array<int>
     */
    private function fileNodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    /**
     * 4-element a32 folder node key (plaintext).
     *
     * @return array<int>
     */
    private function folderNodeKey(): array
    {
        return [0xAABBCCDD, 0xEEFF0011, 0x22334455, 0x66778899];
    }

    /**
     * Encrypt a node key with the master key and return the "owner:encKey" raw key string.
     *
     * @param array<int> $nodeKey Plaintext a32 node key (4 or 8 elements)
     */
    private function encryptedRawKey(array $nodeKey): string
    {
        $masterKeyStr = A32::toString($this->masterKey());
        $enc = Aes::encryptKey($masterKeyStr, $nodeKey);

        return 'OwnerHdl:' . A32::toBase64($enc);
    }

    /**
     * Encrypt attributes with a given node key and return the base64url-encoded ciphertext.
     *
     * @param array<int> $nodeKey Plaintext a32 node key
     */
    private function encodedAttr(string $filename, array $nodeKey): string
    {
        $ciphertext = Attr::encrypt(['n' => $filename], $nodeKey);

        return Base64Url::encode($ciphertext);
    }

    /**
     * Build a Session value object using the shared master key.
     */
    private function session(): Session
    {
        return new Session($this->masterKey(), 'test-session-id', []);
    }

    /**
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeClientCapturingApiRequests(string $apiResponseBody, array &$capturedApiRequests = [], string $downloadBody = ''): Client
    {
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
            'https://g.api.mega.co.nz/',
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $dlMock = new MockHandler([new Response(200, [], $downloadBody)]);
        $dlStack = HandlerStack::create($dlMock);
        $dlHttpClient = new GuzzleClient(['handler' => $dlStack]);

        $downloader = new Downloader($dlHttpClient, $factory);

        return new Client($connector, $downloader, new NullLogger());
    }
}
