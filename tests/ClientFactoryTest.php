<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Config;
use Mega\ClientFactory;
use Mega\Client;
use PHPUnit\Framework\TestCase;

class ClientFactoryTest extends TestCase
{
    public function testCreateReturnsClientInstance(): void
    {
        $factory = new ClientFactory();

        $this->assertInstanceOf(Client::class, $factory->create());
    }

    public function testCreateWithCustomConfig(): void
    {
        $config  = new Config(Config::SERVER_EUROPE);
        $factory = new ClientFactory($config);

        $this->assertInstanceOf(Client::class, $factory->create());
    }
}
