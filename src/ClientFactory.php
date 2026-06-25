<?php

declare(strict_types=1);

namespace Mega;

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

    public function __construct(
        ?Config $config = null,
        ?LoggerInterface $logger = null
    ) {
        $this->config = $config !== null ? $config : new Config();
        $this->logger = $logger !== null ? $logger : new NullLogger();
    }

    public function create(): Client
    {
        return new Client($this->config, $this->logger);
    }
}
