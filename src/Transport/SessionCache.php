<?php

declare(strict_types=1);

namespace Mega\Transport;

use Mega\Entity\Session;
use Psr\Cache\CacheItemPoolInterface;

/**
 * Stores and retrieves Session objects using a PSR-6 cache pool.
 */
class SessionCache
{
    /**
     * Cache key prefix to avoid collisions with other packages.
     */
    const KEY_PREFIX = 'mega_session_';

    /**
     * @var CacheItemPoolInterface
     */
    private $pool;

    public function __construct(CacheItemPoolInterface $pool)
    {
        $this->pool = $pool;
    }

    /**
     * Return a cached Session for the given email, or null on a miss.
     */
    public function get(string $email): ?Session
    {
        $item = $this->pool->getItem($this->key($email));

        if (!$item->isHit()) {
            return null;
        }

        $data = $item->get();

        if (
            !\is_array($data)
            || !isset($data['masterKey'], $data['sessionId'], $data['privateKey'])
            || !\is_array($data['masterKey'])
            || !\is_string($data['sessionId'])
            || !\is_array($data['privateKey'])
        ) {
            return null;
        }

        return new Session($data['masterKey'], $data['sessionId'], $data['privateKey']);
    }

    /**
     * Persist a Session in the cache under the given email key.
     */
    public function set(string $email, Session $session): void
    {
        $item = $this->pool->getItem($this->key($email));
        $item->set([
            'masterKey'  => $session->getMasterKey(),
            'sessionId'  => $session->getSessionId(),
            'privateKey' => $session->getPrivateKey(),
        ]);

        $this->pool->save($item);
    }

    /**
     * Remove a cached Session for the given email.
     */
    public function delete(string $email): void
    {
        $this->pool->deleteItem($this->key($email));
    }

    private function key(string $email): string
    {
        return self::KEY_PREFIX . \sha1($email);
    }
}
