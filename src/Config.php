<?php

declare(strict_types=1);

namespace Mega;

/**
 * Holds configuration for the MEGA client.
 */
class Config
{
    const SERVER_GLOBAL = 'https://g.api.mega.co.nz/';
    const SERVER_EUROPE = 'https://eu.api.mega.co.nz/';

    /**
     * @var string
     */
    private $apiUrl;

    public function __construct(string $apiUrl = self::SERVER_GLOBAL)
    {
        $this->apiUrl = $apiUrl;
    }

    public function getApiUrl(): string
    {
        return $this->apiUrl;
    }
}
