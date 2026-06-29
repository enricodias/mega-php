<?php

declare(strict_types=1);

namespace Mega\Tests\Transport;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Config;
use Mega\Exception\ApiException;
use Mega\Exception\HttpException;
use Mega\Transport\Connector;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;

class ConnectorTest extends TestCase
{
    /**
     * @return array<string, array<mixed>>
     */
    public function apiErrorCodeProvider(): array
    {
        return [
            'EINTERNAL'  => [ApiException::EINTERNAL],
            'EARGS'      => [ApiException::EARGS],
            'EAGAIN'     => [ApiException::EAGAIN],
            'ERATELIMIT' => [ApiException::ERATELIMIT],
            'ENOENT'     => [ApiException::ENOENT],
            'EACCESS'    => [ApiException::EACCESS],
            'ESID'       => [ApiException::ESID],
            'EOVERQUOTA' => [ApiException::EOVERQUOTA],
        ];
    }

    /**
     * @dataProvider apiErrorCodeProvider
     */
    public function testSendThrowsApiExceptionOnErrorCode(int $code): void
    {
        $connector = $this->makeConnector(\json_encode([$code]));

        $this->expectException(ApiException::class);
        $this->expectExceptionCode($code);

        $connector->send(['a' => 'g']);
    }

    public function testSendThrowsApiExceptionWhenTopLevelIsErrorCode(): void
    {
        $connector = $this->makeConnector(\json_encode(ApiException::EINTERNAL));

        $this->expectException(ApiException::class);

        $connector->send(['a' => 'g']);
    }

    public function testSendReturnsUnwrappedResponseElement(): void
    {
        $payload = ['s' => 1234, 'at' => 'abc'];
        $connector = $this->makeConnector(\json_encode([$payload]));

        $result = $connector->send(['a' => 'g', 'p' => 'handle']);

        $this->assertSame($payload, $result);
    }

    public function testSendIncludesSidInUrlWhenSet(): void
    {
        $requests = [];
        $connector = $this->makeConnectorCapturingRequests(\json_encode([['ok' => true]]), $requests);
        $connector->setSessionId('testsid123');
        $connector->send(['a' => 'f']);

        $this->assertStringContainsString('sid=testsid123', (string) $requests[0]->getUri());
    }

    public function testSendOmitsSidFromUrlWhenNotSet(): void
    {
        $requests  = [];
        $connector = $this->makeConnectorCapturingRequests(\json_encode([['ok' => true]]), $requests);
        $connector->send(['a' => 'f']);

        $this->assertStringNotContainsString('sid=', (string) $requests[0]->getUri());
    }

    public function testSendIncrementsSequenceNumber(): void
    {
        $requests  = [];
        $connector = $this->makeConnectorCapturingRequests(
            \json_encode([['ok' => true]]),
            $requests,
            2
        );

        $connector->send(['a' => 'f']);
        $connector->send(['a' => 'f']);

        \preg_match('/id=(\d+)/', (string) $requests[0]->getUri(), $m1);
        \preg_match('/id=(\d+)/', (string) $requests[1]->getUri(), $m2);

        $this->assertSame((int) $m1[1] + 1, (int) $m2[1]);
    }

    public function testSendThrowsHttpExceptionOnMalformedJson(): void
    {
        $connector = $this->makeConnector('not-json');

        $this->expectException(HttpException::class);

        $connector->send(['a' => 'g']);
    }

    private function makeConnector(string $responseBody): Connector
    {
        $ignored = [];
        return $this->makeConnectorCapturingRequests($responseBody, $ignored);
    }

    /**
     * @param array<\Psr\Http\Message\RequestInterface> $capturedRequests
     */
    private function makeConnectorCapturingRequests(
        string $responseBody,
        array &$capturedRequests,
        int $responseCount = 1
    ): Connector {
        $responses = \array_fill(0, $responseCount, new Response(200, [], $responseBody));
        $mock = new MockHandler($responses);
        $stack = HandlerStack::create($mock);

        $stack->push(function (callable $handler) use (&$capturedRequests) {
            return function ($request, array $options) use ($handler, &$capturedRequests) {
                $capturedRequests[] = $request;
                return $handler($request, $options);
            };
        });

        $httpClient = new GuzzleClient(['handler' => $stack]);
        $factory = new HttpFactory();

        return new Connector(
            Config::SERVER_GLOBAL,
            $httpClient,
            $factory,
            $factory,
            new NullLogger()
        );
    }
}
