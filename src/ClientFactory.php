<?php

declare(strict_types=1);

namespace Mega;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\SessionCache;
use Psr\Cache\CacheItemPoolInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Builds Client instances with explicit or auto-discovered PSR dependencies.
 */
class ClientFactory
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var ClientInterface|null
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface|null
     */
    private $requestFactory;

    /**
     * @var StreamFactoryInterface|null
     */
    private $streamFactory;

    /**
     * @var CacheItemPoolInterface|null
     */
    private $cachePool;

    public function __construct(
        ?Config $config = null,
        ?LoggerInterface $logger = null
    ) {
        $this->config = $config !== null ? $config : new Config();
        $this->logger = $logger !== null ? $logger : new NullLogger();
    }

    public function withHttpClient(ClientInterface $httpClient): self
    {
        $clone = clone $this;
        $clone->httpClient = $httpClient;
        return $clone;
    }

    public function withRequestFactory(RequestFactoryInterface $requestFactory): self
    {
        $clone = clone $this;
        $clone->requestFactory = $requestFactory;
        return $clone;
    }

    public function withStreamFactory(StreamFactoryInterface $streamFactory): self
    {
        $clone = clone $this;
        $clone->streamFactory = $streamFactory;
        return $clone;
    }

    public function withCachePool(CacheItemPoolInterface $cachePool): self
    {
        $clone = clone $this;
        $clone->cachePool = $cachePool;
        return $clone;
    }

    public function create(): Client
    {
        $httpClient = $this->httpClient ?? Psr18ClientDiscovery::find();
        $requestFactory = $this->requestFactory ?? Psr17FactoryDiscovery::findRequestFactory();
        $streamFactory = $this->streamFactory ?? Psr17FactoryDiscovery::findStreamFactory();

        $connector = new Connector(
            $this->config->getApiUrl(),
            $httpClient,
            $requestFactory,
            $streamFactory,
            $this->logger
        );

        $downloader = new Downloader($httpClient, $requestFactory);

        $sessionCache = $this->cachePool !== null
            ? new SessionCache($this->cachePool)
            : null;

        return new Client($connector, $downloader, $this->logger, $sessionCache);
    }
}
