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
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\FileMac;
use Mega\Crypto\NodeKey;
use Mega\Entity\Node;
use Mega\Entity\TransferResult;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Service\NodeService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class NodeServiceTest extends TestCase
{
    public function testListNodesReturnsEmptyArrayWhenResponseHasNoFKey(): void
    {
        $apiResponse = \json_encode([[/* no 'f' key */]]);
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse);

        $nodes = $service->listNodes(A32::toString($this->masterKey()));

        $this->assertSame([], $nodes);
    }

    public function testListNodesSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $apiResponse = \json_encode([['f' => []]]);
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $apiRequests);

        $service->listNodes(A32::toString($this->masterKey()));

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
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse);

        $nodes = $service->listNodes(A32::toString($this->masterKey()));

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
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse);

        $nodes = $service->listNodes(A32::toString($this->masterKey()));

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
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse);

        $nodes = $service->listNodes(A32::toString($this->masterKey()));

        $this->assertCount(1, $nodes);
        $this->assertSame('goodHndl', $nodes[0]->getHandle());
    }

    public function testGetFileInfoSendsCorrectCommand(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey = $this->encryptedRawKey($fileKey);
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', $rawKey);

        $encodedAttr = $this->encodedAttr('file.txt', $fileKey);
        $apiResponse = \json_encode([['s' => 512, 'at' => $encodedAttr]]);

        $apiRequests = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $apiRequests);

        $service->getFileInfo($node, A32::toString($this->masterKey()));

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

        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse);

        $info = $service->getFileInfo($node, A32::toString($this->masterKey()));

        $this->assertSame('report.pdf', $info->getName());
        $this->assertSame(2048, $info->getSize());
        $this->assertNull($info->getDownloadUrl());
    }

    public function testDownloadSendsCorrectCommand(): void
    {
        $plaintext = \str_repeat('X', 16);
        $fixture = $this->buildFileFixture($plaintext);
        $rawKey = $this->encryptedRawKey($fixture['nodeKey']);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $apiRequests = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $apiRequests, $fixture['ciphertext']);

        $service->download($node, A32::toString($this->masterKey()));

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('g', $command['a']);
        $this->assertSame('dlFileHd', $command['n']);
        $this->assertSame(1, $command['g']);
    }

    public function testDownloadReturnsDecryptedContent(): void
    {
        $plaintext = \str_repeat('X', 16);
        $fixture = $this->buildFileFixture($plaintext);
        $rawKey = $this->encryptedRawKey($fixture['nodeKey']);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $ignored, $fixture['ciphertext']);

        $result = $service->download($node, A32::toString($this->masterKey()));

        $this->assertSame($plaintext, $result);
    }

    public function testDownloadWritesToDestinationStream(): void
    {
        $plaintext = \str_repeat('X', 16);
        $fixture = $this->buildFileFixture($plaintext);
        $rawKey = $this->encryptedRawKey($fixture['nodeKey']);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $apiResponse = \json_encode([[
            's' => \strlen($plaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $ignored, $fixture['ciphertext']);

        $dest = \fopen('php://memory', 'wb+');
        $bytesWritten = $service->download($node, A32::toString($this->masterKey()), $dest);

        \rewind($dest);
        $this->assertSame($plaintext, \stream_get_contents($dest));
        $this->assertSame(\strlen($plaintext), $bytesWritten);
        \fclose($dest);
    }

    public function testDownloadThrowsOnNon2xxStatus(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey  = $this->encryptedRawKey($fileKey);
        $node    = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $apiResponse = \json_encode([[
            's' => 16,
            'g' => 'https://example.invalid/dl',
        ]]);

        $factory = new HttpFactory();

        $apiMock  = new MockHandler([new Response(200, [], $apiResponse)]);
        $apiStack = HandlerStack::create($apiMock);
        $apiHttpClient = new GuzzleClient(['handler' => $apiStack]);
        $connector = new Connector(
            Config::SERVER_GLOBAL,
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $dlMock  = new MockHandler([new Response(404, [], 'Not Found')]);
        $dlStack = HandlerStack::create($dlMock);
        $dlClient = new GuzzleClient(['handler' => $dlStack]);
        $downloader = new Downloader($dlClient, $factory);
        $uploader = $this->createMock(Uploader::class);

        $service = new NodeService($connector, $downloader, $uploader);

        $this->expectException(HttpException::class);
        $service->download($node, A32::toString($this->masterKey()));
    }

    public function testDownloadThrowsOnTruncatedResponse(): void
    {
        $fileKey = $this->fileNodeKey();
        $rawKey  = $this->encryptedRawKey($fileKey);
        $node    = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        // Tell the API the file is 32 bytes but only return 8 bytes.
        $apiResponse = \json_encode([[
            's' => 32,
            'g' => 'https://example.invalid/dl',
        ]]);

        $factory = new HttpFactory();

        $apiMock  = new MockHandler([new Response(200, [], $apiResponse)]);
        $apiStack = HandlerStack::create($apiMock);
        $apiHttpClient = new GuzzleClient(['handler' => $apiStack]);
        $connector = new Connector(
            Config::SERVER_GLOBAL,
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $dlMock  = new MockHandler([new Response(200, [], \str_repeat("\0", 8))]);
        $dlStack = HandlerStack::create($dlMock);
        $dlClient = new GuzzleClient(['handler' => $dlStack]);
        $downloader = new Downloader($dlClient, $factory);
        $uploader = $this->createMock(Uploader::class);

        $service = new NodeService($connector, $downloader, $uploader);

        $this->expectException(HttpException::class);
        $service->download($node, A32::toString($this->masterKey()));
    }

    public function testDownloadThrowsOnMacMismatch(): void
    {
        // Build a valid fixture for 'X'*16, then serve ciphertext for 'Z'*16
        // using the same node key, the MAC embedded in the key won't match.
        $fixture = $this->buildFileFixture(\str_repeat('X', 16));
        $rawKey = $this->encryptedRawKey($fixture['nodeKey']);
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', $rawKey);

        $tamperedPlaintext = \str_repeat('Z', 16);
        $aesKey = A32::toString(NodeKey::foldToAesKey($fixture['nodeKey']));
        $iv  = ChunkSizer::ivFromNodeKey($fixture['nodeKey']);
        $ciphertext = (string) \openssl_encrypt(
            $tamperedPlaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $apiResponse = \json_encode([[
            's' => \strlen($tamperedPlaintext),
            'g' => 'https://example.invalid/dl',
        ]]);

        $ignored = [];
        $service = $this->makeServiceCapturingApiRequests((string) $apiResponse, $ignored, $ciphertext);

        $this->expectException(CryptoException::class);
        $service->download($node, A32::toString($this->masterKey()));
    }

    public function testUploadRejectsEmptySourceBeforeSendingUploadCommand(): void
    {
        $stream = $this->makeStream('');
        $service = $this->makeServiceCapturingApiRequests('[]');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Cannot upload an empty file.');

        $service->upload($stream, 'parentHd', A32::toString($this->masterKey()), 'empty.bin');
    }

    public function testUploadSendsUploadSizeCommand(): void
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

        $service = $this->makeServiceCapturingTwoApiRequests(
            (string) $uploadUrlResponse,
            (string) $nodeCreateResponse,
            $apiRequests,
            $uploader
        );

        $service->upload($stream, 'parentHd', A32::toString($this->masterKey()), 'test.bin');

        $this->assertCount(2, $apiRequests);

        $firstBody = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $firstBody[0];

        $this->assertSame('u', $command['a']);
        $this->assertSame(\strlen($plaintext), $command['s']);
    }

    public function testUploadSendsNodeCreateCommand(): void
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

        $service = $this->makeServiceCapturingTwoApiRequests(
            (string) $uploadUrlResponse,
            (string) $nodeCreateResponse,
            $apiRequests,
            $uploader
        );

        $service->upload($stream, 'parentHd', A32::toString($this->masterKey()), 'myfile.txt');

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

    public function testUploadNodeCreateContainsDecryptableAttributes(): void
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

        $service = $this->makeServiceCapturingTwoApiRequests(
            (string) $uploadUrlResponse,
            (string) $nodeCreateResponse,
            $apiRequests,
            $uploader
        );

        $service->upload($stream, 'parentHd', A32::toString($this->masterKey()), 'secret.pdf');

        $secondBody = \json_decode((string) $apiRequests[1]->getBody(), true);
        $nodeEntry = $secondBody[0]['n'][0];

        $masterKeyStr = A32::toString($this->masterKey());
        $encKeyA32 = A32::fromBase64($nodeEntry['k']);
        $nodeKey = Aes::decryptKey($masterKeyStr, $encKeyA32);

        $attrCiphertext = Base64Url::decode($nodeEntry['a']);
        $attrs = Attr::decrypt($attrCiphertext, $nodeKey);

        $this->assertSame('secret.pdf', $attrs['n']);
    }

    public function testUploadReturnsTransferResultWithNodeHandle(): void
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

        $service = $this->makeServiceCapturingTwoApiRequests(
            (string) $uploadUrlResponse,
            (string) $nodeCreateResponse,
            $ignored,
            $uploader
        );

        $result = $service->upload($stream, 'parentHd', A32::toString($this->masterKey()), 'file.bin');

        $this->assertInstanceOf(TransferResult::class, $result);
        $this->assertSame('returnedH', $result->getNode()->getHandle());
        $this->assertSame(Node::TYPE_FILE, $result->getNode()->getType());
        $this->assertSame('file.bin', $result->getNode()->getName());
    }

    public function testUploadUsesBasenameFromPathWhenNameOmitted(): void
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

        $service = $this->makeServiceCapturingTwoApiRequests(
            (string) $uploadUrlResponse,
            (string) $nodeCreateResponse,
            $apiRequests,
            $uploader
        );

        $service->upload((string) $tmpFile, 'parentHd', A32::toString($this->masterKey()));

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
     * Words 6 and 7 encode the file MAC for a 16-byte plaintext of str_repeat('X', 16)
     * at offset 0, verified against the AES key derived from this key.
     *
     * @return array<int>
     */
    private function fileNodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x48FB5937, 0xCAA3C09B];
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
     * Build a self-consistent download fixture for a given plaintext.
     *
     * Uses base node key words 0-5 with words 6/7 set to zero for AES key
     * derivation (matching Client::generateNodeKey() before upload). The file
     * MAC is then computed with that AES key and embedded into words 2,3,6,7
     * of the returned node key, exactly as Uploader::upload() does.
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
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeServiceCapturingApiRequests(
        string $apiResponseBody,
        array &$capturedApiRequests = [],
        string $downloadBody = ''
    ): NodeService {
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
        $uploader = $this->createMock(Uploader::class);

        return new NodeService($connector, $downloader, $uploader);
    }

    /**
     * Builds a NodeService whose Connector returns two sequential API
     * responses: the first for the upload-URL command, the second for
     * node-create.
     *
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeServiceCapturingTwoApiRequests(
        string $firstApiResponse,
        string $secondApiResponse,
        array &$capturedApiRequests,
        Uploader $uploader
    ): NodeService {
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

        return new NodeService($connector, $downloader, $uploader);
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
}
