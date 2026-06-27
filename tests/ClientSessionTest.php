<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Client;
use Mega\Entity\Session;
use Mega\Exception\AuthException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\SessionCache;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientSessionTest extends TestCase
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

    public function testLoginReturnsCachedSessionOnCacheHit(): void
    {
        $cached = new Session([5, 6, 7, 8], 'sid-cached', []);
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);

        $sessionCache = $this->createMock(SessionCache::class);
        $sessionCache->method('get')->with('user@example.com')->willReturn($cached);
        $sessionCache->expects($this->never())->method('set');

        $connector->expects($this->never())->method('send');

        $client = new Client($connector, $downloader, new NullLogger(), $sessionCache);
        $result = $client->login('user@example.com', 'password');

        $this->assertSame($cached->getSessionId(), $result->getSessionId());
    }

    public function testRestoreSessionSetsSessionIdOnConnector(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-from-restore', []);
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);

        $connector->expects($this->once())->method('setSessionId')->with('sid-from-restore');

        $client = new Client($connector, $downloader, new NullLogger());
        $client->restoreSession($session);
    }

    private function makeClient(): Client
    {
        $connector = $this->createMock(Connector::class);
        $downloader = $this->createMock(Downloader::class);
        return new Client($connector, $downloader, new NullLogger());
    }
}
