<?php

declare(strict_types=1);

namespace Mega\Tests;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Mega\Client;
use Mega\Config;
use Mega\PsrClientFactory;
use PHPUnit\Framework\TestCase;

class PsrClientFactoryTest extends TestCase
{
    public function testGetClientReturnsClientInstance(): void
    {
        $factory = $this->makeFactory();

        $this->assertInstanceOf(Client::class, $factory->getClient());
    }

    public function testGetClientWithCustomConfig(): void
    {
        $config = new Config(Config::SERVER_EUROPE);
        $factory = $this->makeFactory($config);

        $this->assertInstanceOf(Client::class, $factory->getClient());
    }

    private function makeFactory(?Config $config = null): PsrClientFactory
    {
        $mock = new MockHandler([new Response(200, [], '[]')]);
        $stack = HandlerStack::create($mock);
        $guzzle = new GuzzleClient(['handler' => $stack]);

        return new PsrClientFactory($config, $guzzle);
    }
}
