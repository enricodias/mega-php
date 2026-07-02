<?php

declare(strict_types=1);

namespace Mega;

use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Builds a Client from constructor-injected PSR dependencies.
 *
 * Intended for dependency injection containers that can autowire typed
 * constructor parameters but cannot invoke fluent builder methods.
 * Applications without a DI container should use ClientFactory instead.
 */
class PsrClientFactory
{
    /**
     * @var Client
     */
    private $client;

    public function __construct(
        ?Config $config = null,
        ?ClientInterface $httpClient = null,
        ?RequestFactoryInterface $requestFactory = null,
        ?StreamFactoryInterface $streamFactory = null,
        ?CacheItemPoolInterface $cachePool = null,
        ?LoggerInterface $logger = null
    ) {
        $factory = new ClientFactory($config, $logger);

        if ($httpClient !== null) {
            $factory = $factory->withHttpClient($httpClient);
        }

        if ($requestFactory !== null) {
            $factory = $factory->withRequestFactory($requestFactory);
        }

        if ($streamFactory !== null) {
            $factory = $factory->withStreamFactory($streamFactory);
        }

        if ($cachePool !== null) {
            $factory = $factory->withCachePool($cachePool);
        }

        $this->client = $factory->create();
    }

    public function getClient(): Client
    {
        return $this->client;
    }
}
