<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Crypto\A32;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Exception\AuthException;
use Mega\Exception\HttpException;
use Mega\Service\NodeService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientDownloadTest extends TestCase
{
    public function testDownloadFileRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('download');

        $client = $this->makeClient($nodeService);

        $this->expectException(AuthException::class);

        $client->downloadFile($node);
    }

    public function testDownloadFileDelegatesToNodeServiceWithoutDestination(): void
    {
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', 'owner:key');
        $masterKeyStr = A32::toString($this->masterKey());

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('download')
            ->with($node, $masterKeyStr, null)
            ->willReturn('decrypted content');

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $result = $client->downloadFile($node);

        $this->assertSame('decrypted content', $result);
    }

    public function testDownloadFileDelegatesToNodeServiceWithDestination(): void
    {
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', 'owner:key');
        $masterKeyStr = A32::toString($this->masterKey());
        $dest = \fopen('php://memory', 'wb+');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('download')
            ->with($node, $masterKeyStr, $dest)
            ->willReturn(16);

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $result = $client->downloadFile($node, $dest);

        $this->assertSame(16, $result);

        \fclose($dest);
    }

    public function testDownloadFilePropagatesExceptionsFromService(): void
    {
        $node = new Node('dlFileHd', Node::TYPE_FILE, 'file.bin', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('download')->willThrowException(new HttpException('download failed'));

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $this->expectException(HttpException::class);

        $client->downloadFile($node);
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
