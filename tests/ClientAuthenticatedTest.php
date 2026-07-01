<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Crypto\A32;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Exception\CryptoException;
use Mega\Service\NodeService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientAuthenticatedTest extends TestCase
{
    public function testListNodesRequiresSession(): void
    {
        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('listNodes');

        $client = $this->makeClient($nodeService);

        $this->expectException(AuthException::class);

        $client->listNodes();
    }

    public function testListNodesDelegatesToNodeService(): void
    {
        $node = new Node('fileHndl', Node::TYPE_FILE, 'file.txt', 'owner:key');
        $masterKeyStr = A32::toString($this->masterKey());

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('listNodes')
            ->with($masterKeyStr)
            ->willReturn([$node]);

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertSame([$node], $nodes);
    }

    public function testListNodesPropagatesExceptionsFromService(): void
    {
        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('listNodes')->willThrowException(ApiException::fromCode(ApiException::ENOENT));

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $this->expectException(ApiException::class);

        $client->listNodes();
    }

    public function testGetFileInfoRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('getFileInfo');

        $client = $this->makeClient($nodeService);

        $this->expectException(AuthException::class);

        $client->getFileInfo($node);
    }

    public function testGetFileInfoDelegatesToNodeService(): void
    {
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', 'owner:key');
        $fileInfo = new FileInfo('report.pdf', 2048, null);
        $masterKeyStr = A32::toString($this->masterKey());

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('getFileInfo')
            ->with($node, $masterKeyStr)
            ->willReturn($fileInfo);

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $result = $client->getFileInfo($node);

        $this->assertSame($fileInfo, $result);
    }

    public function testGetFileInfoPropagatesExceptionsFromService(): void
    {
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('getFileInfo')->willThrowException(new CryptoException('bad key'));

        $client = $this->makeClient($nodeService);
        $client->restoreSession($this->session());

        $this->expectException(CryptoException::class);

        $client->getFileInfo($node);
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
