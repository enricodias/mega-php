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

    /**
     * @var string|null
     */
    private $email;

    /**
     * @var string|null
     */
    private $password;

    public function __construct(
        string $apiUrl = self::SERVER_GLOBAL,
        ?string $email = null,
        ?string $password = null
    ) {
        $this->apiUrl = $apiUrl;
        $this->email = $email;
        $this->password = $password;
    }

    public function getApiUrl(): string
    {
        return $this->apiUrl;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }
}
