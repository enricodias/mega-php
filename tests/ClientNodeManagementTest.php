<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Entity\Session;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Service\NodeManagementService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientNodeManagementTest extends TestCase
{
    public function testDeleteNodeRequiresSession(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->expects($this->never())->method('delete');

        $client = $this->makeClient($nodeManagementService);

        $this->expectException(AuthException::class);

        $client->deleteNode('fileHndl');
    }

    public function testDeleteNodeDelegatesToNodeManagementService(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->expects($this->once())
            ->method('delete')
            ->with('fileHndl');

        $client = $this->makeClient($nodeManagementService);
        $client->restoreSession($this->session());

        $client->deleteNode('fileHndl');
    }

    public function testDeleteNodePropagatesExceptionsFromService(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->method('delete')->willThrowException(ApiException::fromCode(ApiException::ENOENT));

        $client = $this->makeClient($nodeManagementService);
        $client->restoreSession($this->session());

        $this->expectException(ApiException::class);

        $client->deleteNode('missingHd');
    }

    public function testMoveNodeRequiresSession(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->expects($this->never())->method('move');

        $client = $this->makeClient($nodeManagementService);

        $this->expectException(AuthException::class);

        $client->moveNode('fileHndl', 'parentHd');
    }

    public function testMoveNodeDelegatesToNodeManagementService(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->expects($this->once())
            ->method('move')
            ->with('fileHndl', 'parentHd');

        $client = $this->makeClient($nodeManagementService);
        $client->restoreSession($this->session());

        $client->moveNode('fileHndl', 'parentHd');
    }

    public function testMoveNodePropagatesExceptionsFromService(): void
    {
        $nodeManagementService = $this->createMock(NodeManagementService::class);
        $nodeManagementService->method('move')->willThrowException(ApiException::fromCode(ApiException::ENOENT));

        $client = $this->makeClient($nodeManagementService);
        $client->restoreSession($this->session());

        $this->expectException(ApiException::class);

        $client->moveNode('missingHd', 'parentHd');
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

    private function makeClient(NodeManagementService $nodeManagementService): Client
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
            $nodeManagementService
        );
    }
}
