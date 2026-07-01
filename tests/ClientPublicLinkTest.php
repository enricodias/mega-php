<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Entity\FileInfo;
use Mega\Exception\InvalidLinkException;
use Mega\Service\PublicFileService;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientPublicLinkTest extends TestCase
{
    public function testGetPublicFileInfoDelegatesToPublicFileService(): void
    {
        $link = 'https://mega.nz/file/AbCdEfGh#linkKey';
        $fileInfo = new FileInfo('hello.txt', 1234, null);

        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->expects($this->once())
            ->method('getFileInfo')
            ->with($link)
            ->willReturn($fileInfo);

        $client = $this->makeClient($publicFileService);
        $result = $client->getPublicFileInfo($link);

        $this->assertSame($fileInfo, $result);
    }

    public function testGetPublicFileInfoPropagatesExceptionsFromService(): void
    {
        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->method('getFileInfo')
            ->willThrowException(new InvalidLinkException('not a mega link'));

        $client = $this->makeClient($publicFileService);

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

        $client = $this->makeClient($publicFileService);
        $result = $client->downloadPublicFile($link, $dest);

        $this->assertSame(16, $result);

        \fclose($dest);
    }

    public function testDownloadPublicFilePropagatesExceptionsFromService(): void
    {
        $publicFileService = $this->createMock(PublicFileService::class);
        $publicFileService->method('download')
            ->willThrowException(new InvalidLinkException('folder link'));

        $client = $this->makeClient($publicFileService);

        $this->expectException(InvalidLinkException::class);

        $client->downloadPublicFile('https://mega.nz/folder/FolderHnd#linkKey');
    }

    private function makeClient(PublicFileService $publicFileService): Client
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
            $publicFileService
        );
    }
}
