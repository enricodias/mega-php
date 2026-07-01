<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\NodeKey;
use PHPUnit\Framework\TestCase;

class NodeKeyTest extends TestCase
{
    /**
     * @return array<string, array<mixed>>
     */
    public function foldToAesKeyProvider(): array
    {
        return [
            'identity for 4-element key' => [
                [0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC],
                [0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC],
            ],
            'xor-fold 8-element key' => [
                [0x01010101, 0x02020202, 0x03030303, 0x04040404,
                 0x10101010, 0x20202020, 0x30303030, 0x40404040],
                [0x11111111, 0x22222222, 0x33333333, 0x44444444],
            ],
            'all zeros 8-element' => [
                [0, 0, 0, 0, 0, 0, 0, 0],
                [0, 0, 0, 0],
            ],
            'identity XOR (same halves)' => [
                [0xDEADBEEF, 0xCAFEBABE, 0x01234567, 0x89ABCDEF,
                 0xDEADBEEF, 0xCAFEBABE, 0x01234567, 0x89ABCDEF],
                [0, 0, 0, 0],
            ],
        ];
    }

    /**
     * @dataProvider foldToAesKeyProvider
     *
     * @param array<int> $nodeKey
     * @param array<int> $expected
     */
    public function testFoldToAesKey(array $nodeKey, array $expected): void
    {
        $this->assertSame($expected, NodeKey::foldToAesKey($nodeKey));
    }

    public function testDecryptNodeKeyRoundtrip(): void
    {
        // Simulate how MEGA stores a node key: AES-CBC-encrypt the node key
        // with the master key, store it as base64url, then confirm decryptNodeKey
        // recovers the original.
        $masterKey = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];
        $masterKeyStr = A32::toString($masterKey);

        $originalNodeKey = [0xAABBCCDD, 0x11223344, 0x55667788, 0x99AABBCC];

        // Encrypt as MEGA would: AES-CBC of the 4-word key
        $encBin = Aes::encryptCbc($masterKeyStr, A32::toString($originalNodeKey));
        $encA32 = A32::fromString($encBin);
        $encB64 = A32::toBase64($encA32);
        $rawKey = 'uHZ1:' . $encB64;

        $decrypted = NodeKey::decryptNodeKey($rawKey, $masterKeyStr);

        $this->assertSame($originalNodeKey, $decrypted);
    }

    public function testDecryptNodeKeyPicksFirstSegment(): void
    {
        $masterKey = [0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210];
        $masterKeyStr = A32::toString($masterKey);

        $originalNodeKey = [0x10203040, 0x50607080, 0x90a0b0c0, 0xd0e0f001];
        $encBin = Aes::encryptCbc($masterKeyStr, A32::toString($originalNodeKey));
        $encA32 = A32::fromString($encBin);
        $encB64 = A32::toBase64($encA32);

        // Multiple segments separated by "/", only the first should be used
        $rawKey = 'userA:' . $encB64 . '/userB:ZmFrZWtleQ';
        $decrypted = NodeKey::decryptNodeKey($rawKey, $masterKeyStr);

        $this->assertSame($originalNodeKey, $decrypted);
    }
}
