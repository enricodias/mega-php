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
use Mega\ClientFactory;
use PHPUnit\Framework\TestCase;

class ClientFactoryTest extends TestCase
{
    public function testCreateReturnsClientInstance(): void
    {
        $factory = $this->makeFactory();

        $this->assertInstanceOf(Client::class, $factory->create());
    }

    public function testCreateWithCustomConfig(): void
    {
        $config  = new Config(Config::SERVER_EUROPE);
        $factory = $this->makeFactory($config);

        $this->assertInstanceOf(Client::class, $factory->create());
    }

    // --- helpers -------------------------------------------------------------

    private function makeFactory(?Config $config = null): ClientFactory
    {
        $mock      = new MockHandler([new Response(200, [], '[]')]);
        $stack     = HandlerStack::create($mock);
        $guzzle    = new GuzzleClient(['handler' => $stack]);
        $factory   = new HttpFactory();

        return (new ClientFactory($config))
            ->withHttpClient($guzzle)
            ->withRequestFactory($factory)
            ->withStreamFactory($factory);
    }
}
