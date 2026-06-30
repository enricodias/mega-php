<?php

declare(strict_types=1);

namespace Mega\Entity;

/**
 * Represents an authenticated user session.
 */
class Session
{
    /**
     * @var array<int>
     */
    private $masterKey;

    /**
     * @var string
     */
    private $sessionId;

    /**
     * @var array<mixed>
     */
    private $privateKey;

    /**
     * @param array<int>   $masterKey
     * @param string       $sessionId
     * @param array<mixed> $privateKey
     */
    public function __construct(array $masterKey, string $sessionId, array $privateKey)
    {
        $this->masterKey = $masterKey;
        $this->sessionId = $sessionId;
        $this->privateKey = $privateKey;
    }

    /**
     * @return array<int>
     */
    public function getMasterKey(): array
    {
        return $this->masterKey;
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    /**
     * @return array<mixed>
     */
    public function getPrivateKey(): array
    {
        return $this->privateKey;
    }
}
