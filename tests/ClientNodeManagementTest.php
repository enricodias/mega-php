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
use Mega\Entity\Session;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ClientNodeManagementTest extends TestCase
{
    public function testDeleteNodeRequiresSession(): void
    {
        $client = $this->makeClientCapturingApiRequests('[0]');

        $this->expectException(AuthException::class);

        $client->deleteNode('fileHndl');
    }

    public function testDeleteNodeRejectsEmptyHandle(): void
    {
        $client = $this->makeClientCapturingApiRequests('[0]');
        $client->restoreSession($this->session());

        $this->expectException(\InvalidArgumentException::class);

        $client->deleteNode('');
    }

    public function testDeleteNodeSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests('[0]', $apiRequests);
        $client->restoreSession($this->session());

        $client->deleteNode('fileHndl');

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('d', $command['a']);
        $this->assertSame('fileHndl', $command['n']);
    }

    public function testDeleteNodePropagatesApiErrors(): void
    {
        $client = $this->makeClientCapturingApiRequests('[-9]');
        $client->restoreSession($this->session());

        $this->expectException(ApiException::class);

        $client->deleteNode('missingHd');
    }

    public function testMoveNodeRequiresSession(): void
    {
        $client = $this->makeClientCapturingApiRequests('[0]');

        $this->expectException(AuthException::class);

        $client->moveNode('fileHndl', 'parentHd');
    }

    public function testMoveNodeRejectsEmptyHandle(): void
    {
        $client = $this->makeClientCapturingApiRequests('[0]');
        $client->restoreSession($this->session());

        $this->expectException(\InvalidArgumentException::class);

        $client->moveNode('', 'parentHd');
    }

    public function testMoveNodeRejectsEmptyParentHandle(): void
    {
        $client = $this->makeClientCapturingApiRequests('[0]');
        $client->restoreSession($this->session());

        $this->expectException(\InvalidArgumentException::class);

        $client->moveNode('fileHndl', '');
    }

    public function testMoveNodeSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $client = $this->makeClientCapturingApiRequests('[0]', $apiRequests);
        $client->restoreSession($this->session());

        $client->moveNode('fileHndl', 'parentHd');

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('m', $command['a']);
        $this->assertSame('fileHndl', $command['n']);
        $this->assertSame('parentHd', $command['t']);
    }

    public function testMoveNodePropagatesApiErrors(): void
    {
        $client = $this->makeClientCapturingApiRequests('[-9]');
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

    /**
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeClientCapturingApiRequests(string $apiResponseBody, array &$capturedApiRequests = []): Client
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
            Config::SERVER_GLOBAL,
            $apiHttpClient,
            $factory,
            $factory,
            new NullLogger()
        );

        $downloader = $this->createMock(Downloader::class);
        $uploader = $this->createMock(Uploader::class);

        return new Client($connector, $downloader, $uploader, new NullLogger());
    }
}