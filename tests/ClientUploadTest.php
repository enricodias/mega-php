<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Crypto\A32;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Entity\TransferResult;
use Mega\Exception\AuthException;
use Mega\Service\NodeService;
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

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('upload');

        $client = $this->makeClient($nodeService);

        $this->expectException(AuthException::class);

        $client->uploadFile($stream, 'parentHd');
    }

    public function testUploadFileDelegatesToNodeService(): void
    {
        $stream = \fopen('php://memory', 'rb+');
        $masterKeyStr = A32::toString($this->masterKey());
        $node = new Node('newHndl', Node::TYPE_FILE, 'file.bin', 'owner:key');
        $transferResult = new TransferResult($node);

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('upload')
            ->with($stream, 'parentHd', $masterKeyStr, 'file.bin')
            ->willReturn($transferResult);

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $result = $client->uploadFile($stream, 'parentHd', 'file.bin');

        $this->assertSame($transferResult, $result);
    }

    public function testUploadFilePropagatesExceptionsFromService(): void
    {
        $stream = \fopen('php://memory', 'rb+');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('upload')->willThrowException(
            new \InvalidArgumentException('Cannot upload an empty file.')
        );

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $this->expectException(\InvalidArgumentException::class);

        $client->uploadFile($stream, 'parentHd');
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

    private function session(): Session
    {
        return new Session($this->masterKey(), 'test-session-id', []);
    }

    private function makeClient(NodeService $nodeService): Client
    {
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);

        return new Client(
            $connector,
            $downloader,
            $uploader,
            new NullLogger(),
            null,
            null,
            null,
            null,
            $nodeService
        );
    }
}
