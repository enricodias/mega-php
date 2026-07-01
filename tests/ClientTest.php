<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Exception\InvalidLinkException;
use Mega\Service\NodeManagementService;
use Mega\Service\NodeService;
use Mega\Service\PublicFileService;
use Mega\Service\SessionAuthenticator;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\SessionCache;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientTest extends TestCase
{
    public function testRestoreSessionAndExportRoundtrip(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-test', []);
        $client = $this->makeClient();

        $client->restoreSession($session);

        $exported = $client->exportSession();

        $this->assertSame($session->getMasterKey(), $exported->getMasterKey());
        $this->assertSame($session->getSessionId(), $exported->getSessionId());
        $this->assertSame($session->getPrivateKey(), $exported->getPrivateKey());
    }

    public function testExportSessionThrowsWhenNoSessionActive(): void
    {
        $client = $this->makeClient();

        $this->expectException(AuthException::class);

        $client->exportSession();
    }

    public function testRestoreSessionSetsSessionIdOnConnector(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-from-restore', []);
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);

        $connector->expects($this->once())->method('setSessionId')->with('sid-from-restore');

        $client = new Client($connector, $downloader, $uploader, new NullLogger());
        $client->restoreSession($session);
    }

    public function testLoginReturnsCachedSessionOnCacheHit(): void
    {
        $cached = new Session([5, 6, 7, 8], 'sid-cached', []);
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);
        $sessionAuthenticator = $this->createMock(SessionAuthenticator::class);

        $sessionCache = $this->createMock(SessionCache::class);
        $sessionCache->method('get')->with('user@example.com')->willReturn($cached);
        $sessionCache->expects($this->never())->method('set');

        $connector->expects($this->never())->method('send');
        $sessionAuthenticator->expects($this->never())->method('buildSessionFromLoginResponse');

        $client = new Client($connector, $downloader, $uploader, new NullLogger(), $sessionCache, $sessionAuthenticator);
        $result = $client->login('user@example.com', 'password');

        $this->assertSame($cached->getSessionId(), $result->getSessionId());
    }

    public function testLoginDelegatesToSessionAuthenticatorOnCacheMiss(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-from-login', []);
        $apiResponse = ['k' => 'response-from-api'];
        $passwordKey = Aes::deriveKeyFromPassword('password');

        $connector = $this->createMock(Connector::class);
        $connector->method('send')->willReturn($apiResponse);
        $connector->expects($this->once())->method('setSessionId')->with('sid-from-login');

        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);

        $sessionAuthenticator = $this->createMock(SessionAuthenticator::class);
        $sessionAuthenticator->expects($this->once())
            ->method('buildSessionFromLoginResponse')
            ->with($apiResponse, $passwordKey)
            ->willReturn($session);

        $client = new Client($connector, $downloader, $uploader, new NullLogger(), null, $sessionAuthenticator);
        $result = $client->login('user@example.com', 'password');

        $this->assertSame($session, $result);
    }

    public function testLoginCachesSessionBuiltBySessionAuthenticator(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-from-login', []);

        $connector = $this->createMock(Connector::class);
        $connector->method('send')->willReturn(['k' => 'response-from-api']);

        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);

        $sessionAuthenticator = $this->createMock(SessionAuthenticator::class);
        $sessionAuthenticator->method('buildSessionFromLoginResponse')->willReturn($session);

        $sessionCache = $this->createMock(SessionCache::class);
        $sessionCache->method('get')->with('user@example.com')->willReturn(null);
        $sessionCache->expects($this->once())->method('set')->with('user@example.com', $session);

        $client = new Client($connector, $downloader, $uploader, new NullLogger(), $sessionCache, $sessionAuthenticator);
        $client->login('user@example.com', 'password');
    }

    public function testListNodesRequiresSession(): void
    {
        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('listNodes');

        $client = $this->makeClient(null, null, $nodeService);

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

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $nodes = $client->listNodes();

        $this->assertSame([$node], $nodes);
    }

    public function testListNodesPropagatesExceptionsFromService(): void
    {
        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('listNodes')->willThrowException(ApiException::fromCode(ApiException::ENOENT));

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $this->expectException(ApiException::class);

        $client->listNodes();
    }

    public function testGetFileInfoRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('getFileInfo');

        $client = $this->makeClient(null, null, $nodeService);

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

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $result = $client->getFileInfo($node);

        $this->assertSame($fileInfo, $result);
    }

    public function testGetFileInfoPropagatesExceptionsFromService(): void
    {
        $node = new Node('myFileHd', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('getFileInfo')->willThrowException(new CryptoException('bad key'));

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $this->expectException(CryptoException::class);

        $client->getFileInfo($node);
    }

    public function testDownloadFileRequiresSession(): void
    {
        $node = new Node('handle1', Node::TYPE_FILE, 'file.txt', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('download');

        $client = $this->makeClient(null, null, $nodeService);

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

        $client = $this->makeClient(null, null, $nodeService);
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

        $client = $this->makeClient(null, null, $nodeService);
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

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $this->expectException(HttpException::class);

        $client->downloadFile($node);
    }

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

    public function testGetPublicFileInfoDelegatesToPublicFileService(): void
    {
        $link = 'https://mega.nz/file/AbCdEfGh#linkKey';
        $fileInfo = new FileInfo('hello.txt', 1234, null);

        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->expects($this->once())
            ->method('getFileInfo')
            ->with($link)
            ->willReturn($fileInfo);

        $client = $this->makeClient(null, $publicFileService);
        $result = $client->getPublicFileInfo($link);

        $this->assertSame($fileInfo, $result);
    }

    public function testGetPublicFileInfoPropagatesExceptionsFromService(): void
    {
        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->method('getFileInfo')
            ->willThrowException(new InvalidLinkException('not a mega link'));

        $client = $this->makeClient(null, $publicFileService);

        $this->expectException(InvalidLinkException::class);

        $client->getPublicFileInfo('https://not-a-mega-link.example.com/');
    }

    public function testDownloadPublicFileDelegatesToPublicFileService(): void
    {
        $link = 'https://mega.nz/file/AbCdEfGh#linkKey';
        $dest = \fopen('php://memory', 'wb+');

        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->expects($this->once())
            ->method('download')
            ->with($link, $dest)
            ->willReturn(16);

        $client = $this->makeClient(null, $publicFileService);
        $result = $client->downloadPublicFile($link, $dest);

        $this->assertSame(16, $result);

        \fclose($dest);
    }

    public function testDownloadPublicFilePropagatesExceptionsFromService(): void
    {
        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->method('download')
            ->willThrowException(new InvalidLinkException('folder link'));

        $client = $this->makeClient(null, $publicFileService);

        $this->expectException(InvalidLinkException::class);

        $client->downloadPublicFile('https://mega.nz/folder/FolderHnd#linkKey');
    }

    public function testUploadFileRequiresSession(): void
    {
        $stream = \fopen('php://memory', 'rb+');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->never())->method('upload');

        $client = $this->makeClient(null, null, $nodeService);

        $this->expectException(AuthException::class);

        $client->uploadFile($stream, 'parentHd');
    }

    public function testUploadFileDelegatesToNodeService(): void
    {
        $stream = \fopen('php://memory', 'rb+');
        $masterKeyStr = A32::toString($this->masterKey());
        $node = new Node('newHndl', Node::TYPE_FILE, 'file.bin', 'owner:key');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->expects($this->once())
            ->method('upload')
            ->with($stream, 'parentHd', $masterKeyStr, 'file.bin')
            ->willReturn($node);

        $client = $this->makeClient(null, null, $nodeService);
        $client->restoreSession($this->session());

        $result = $client->uploadFile($stream, 'parentHd', 'file.bin');

        $this->assertSame($node, $result);
    }

    public function testUploadFilePropagatesExceptionsFromService(): void
    {
        $stream = \fopen('php://memory', 'rb+');

        $nodeService = $this->createMock(NodeService::class);
        $nodeService->method('upload')->willThrowException(
            new \InvalidArgumentException('Cannot upload an empty file.')
        );

        $client = $this->makeClient(null, null, $nodeService);
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

    private function makeClient(
        ?NodeManagementService $nodeManagementService = null,
        ?PublicFileService $publicFileService = null,
        ?NodeService $nodeService = null
    ): Client {
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
            $nodeManagementService,
            $publicFileService,
            $nodeService
        );
    }
}
