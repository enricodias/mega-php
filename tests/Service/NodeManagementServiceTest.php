<?php

declare(strict_types=1);

namespace Mega\Tests\Service;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Config;
use Mega\Exception\ApiException;
use Mega\Service\NodeManagementService;
use Mega\Transport\Connector;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class NodeManagementServiceTest extends TestCase
{
    public function testDeleteRejectsEmptyHandle(): void
    {
        $service = $this->makeService('[0]');

        $this->expectException(\InvalidArgumentException::class);

        $service->delete('');
    }

    public function testDeleteSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $service = $this->makeService('[0]', $apiRequests);

        $service->delete('fileHndl');

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('d', $command['a']);
        $this->assertSame('fileHndl', $command['n']);
    }

    public function testDeletePropagatesApiErrors(): void
    {
        $service = $this->makeService('[-9]');

        $this->expectException(ApiException::class);

        $service->delete('missingHd');
    }

    /**
     * @dataProvider moveInvalidHandleProvider
     */
    public function testMoveRejectsEmptyHandles(string $handle, string $parentHandle): void
    {
        $service = $this->makeService('[0]');

        $this->expectException(\InvalidArgumentException::class);

        $service->move($handle, $parentHandle);
    }

    /**
     * @return array<string, array{0: string, 1: string}>
     */
    public function moveInvalidHandleProvider(): array
    {
        return [
            'empty handle' => ['', 'parentHd'],
            'empty parent handle' => ['fileHndl', ''],
        ];
    }

    public function testMoveSendsCorrectCommand(): void
    {
        $apiRequests = [];
        $service = $this->makeService('[0]', $apiRequests);

        $service->move('fileHndl', 'parentHd');

        $this->assertCount(1, $apiRequests);

        $body = \json_decode((string) $apiRequests[0]->getBody(), true);
        $command = $body[0];

        $this->assertSame('m', $command['a']);
        $this->assertSame('fileHndl', $command['n']);
        $this->assertSame('parentHd', $command['t']);
    }

    public function testMovePropagatesApiErrors(): void
    {
        $service = $this->makeService('[-9]');

        $this->expectException(ApiException::class);

        $service->move('missingHd', 'parentHd');
    }

    /**
     * @param array<\Psr\Http\Message\RequestInterface> $capturedApiRequests
     */
    private function makeService(string $apiResponseBody, array &$capturedApiRequests = []): NodeManagementService
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

        return new NodeManagementService($connector);
    }
}
