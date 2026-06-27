<?php

declare(strict_types=1);

namespace Mega\Tests\Transport;

use Mega\Entity\Session;
use Mega\Transport\SessionCache;
use PHPUnit\Framework\TestCase;
use Psr\Cache\CacheItemInterface;
use Psr\Cache\CacheItemPoolInterface;

class SessionCacheTest extends TestCase
{
    private const EMAIL = 'user@example.com';

    public function testGetReturnsCachedSession(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-abc', [[1], [2]]);

        $item = $this->makeCacheItem(true, [
            'masterKey'  => $session->getMasterKey(),
            'sessionId'  => $session->getSessionId(),
            'privateKey' => $session->getPrivateKey(),
        ]);

        $pool  = $this->makePool($item);
        $cache = new SessionCache($pool);

        $result = $cache->get(self::EMAIL);

        $this->assertNotNull($result);
        $this->assertSame($session->getMasterKey(), $result->getMasterKey());
        $this->assertSame($session->getSessionId(), $result->getSessionId());
        $this->assertSame($session->getPrivateKey(), $result->getPrivateKey());
    }

    public function testGetReturnsNullOnCacheMiss(): void
    {
        $item = $this->makeCacheItem(false, null);
        $pool = $this->makePool($item);
        $cache = new SessionCache($pool);

        $this->assertNull($cache->get(self::EMAIL));
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function invalidCacheDataProvider(): array
    {
        return [
            'not an array'         => ['just-a-string'],
            'missing masterKey'    => [['sessionId' => 'x', 'privateKey' => []]],
            'missing sessionId'    => [['masterKey' => [], 'privateKey' => []]],
            'missing privateKey'   => [['masterKey' => [], 'sessionId' => 'x']],
            'sessionId not string' => [['masterKey' => [], 'sessionId' => 42, 'privateKey' => []]],
            'masterKey not array'  => [['masterKey' => 'bad', 'sessionId' => 'x', 'privateKey' => []]],
            'privateKey not array' => [['masterKey' => [], 'sessionId' => 'x', 'privateKey' => 'bad']],
        ];
    }

    /**
     * @dataProvider invalidCacheDataProvider
     *
     * @param mixed $data
     */
    public function testGetReturnsNullForCorruptCacheData($data): void
    {
        $item = $this->makeCacheItem(true, $data);
        $pool = $this->makePool($item);
        $cache = new SessionCache($pool);

        $this->assertNull($cache->get(self::EMAIL));
    }

    public function testSetSavesSessionToPool(): void
    {
        $session = new Session([1, 2, 3, 4], 'sid-xyz', []);
        $saved = null;

        $item = $this->createMock(CacheItemInterface::class);
        $item->method('set')->willReturnCallback(function ($value) use ($item, &$saved) {
            $saved = $value;
            return $item;
        });

        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->method('getItem')->willReturn($item);
        $pool->expects($this->once())->method('save')->with($item);

        $cache = new SessionCache($pool);
        $cache->set(self::EMAIL, $session);

        $this->assertIsArray($saved);
        $this->assertSame($session->getMasterKey(), $saved['masterKey']);
        $this->assertSame($session->getSessionId(), $saved['sessionId']);
        $this->assertSame($session->getPrivateKey(), $saved['privateKey']);
    }

    public function testDeleteRemovesItemFromPool(): void
    {
        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->expects($this->once())
            ->method('deleteItem')
            ->with($this->stringContains(SessionCache::KEY_PREFIX));

        $cache = new SessionCache($pool);
        $cache->delete(self::EMAIL);
    }

    public function testKeyIsDeterministicForSameEmail(): void
    {
        $receivedKeys = [];

        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);

        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->method('getItem')->willReturnCallback(function (string $key) use ($item, &$receivedKeys) {
            $receivedKeys[] = $key;
            return $item;
        });

        $cache = new SessionCache($pool);
        $cache->get(self::EMAIL);
        $cache->get(self::EMAIL);

        $this->assertSame($receivedKeys[0], $receivedKeys[1]);
    }

    public function testKeyDiffersForDifferentEmails(): void
    {
        $receivedKeys = [];

        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn(false);

        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->method('getItem')->willReturnCallback(function (string $key) use ($item, &$receivedKeys) {
            $receivedKeys[] = $key;
            return $item;
        });

        $cache = new SessionCache($pool);
        $cache->get('alice@example.com');
        $cache->get('bob@example.com');

        $this->assertNotSame($receivedKeys[0], $receivedKeys[1]);
    }

    /**
     * @param mixed $data
     */
    private function makeCacheItem(bool $isHit, $data): CacheItemInterface
    {
        $item = $this->createMock(CacheItemInterface::class);
        $item->method('isHit')->willReturn($isHit);
        $item->method('get')->willReturn($data);
        return $item;
    }

    private function makePool(CacheItemInterface $item): CacheItemPoolInterface
    {
        $pool = $this->createMock(CacheItemPoolInterface::class);
        $pool->method('getItem')->willReturn($item);
        return $pool;
    }
}
