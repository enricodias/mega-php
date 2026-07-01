<?php

declare(strict_types=1);

namespace Mega\Crypto;

use Mega\Exception\CryptoException;

/**
 * Node key helpers.
 *
 * MEGA stores file node keys as 8-element a32 arrays. The lower four words
 * encode the AES-CTR IV and the file MAC seed, while the upper four words
 * XOR-combined with the lower four produce the actual 128-bit AES key.
 *
 * Folder node keys are 4-element arrays and are used directly as the AES key.
 */
class NodeKey
{
    /**
     * XOR-fold an 8-element file node key down to the 4-element AES key.
     *
     * For 4-element keys (folder nodes) the array is returned unchanged.
     *
     * @param array<int> $nodeKey 4- or 8-element a32 node key
     *
     * @return array<int> 4-element a32 AES key
     */
    public static function foldToAesKey(array $nodeKey): array
    {
        if (\count($nodeKey) === 4) {
            return $nodeKey;
        }

        return [
            $nodeKey[0] ^ $nodeKey[4],
            $nodeKey[1] ^ $nodeKey[5],
            $nodeKey[2] ^ $nodeKey[6],
            $nodeKey[3] ^ $nodeKey[7],
        ];
    }

    /**
     * Decrypt a raw node key string using the session master key.
     *
     * The raw key string contains one or more "owner:encryptedKey" segments
     * separated by "/". The first segment's key is decrypted and returned.
     *
     * @param string $rawKey       Raw node key field from the API (e.g. "uHZ1:AbCd...")
     * @param string $masterKeyStr 16-byte master key as a raw string
     *
     * @return array<int> Decrypted a32 node key (4 or 8 elements)
     *
     * @throws CryptoException
     */
    public static function decryptNodeKey(string $rawKey, string $masterKeyStr): array
    {
        $firstSegment = \explode('/', $rawKey)[0];
        $parts = \explode(':', $firstSegment, 2);
        $encKey = $parts[1] ?? '';

        if ($encKey === '') {
            throw new CryptoException('Node key field is missing the encrypted key portion.');
        }

        $encA32 = A32::fromBase64($encKey);

        if (\count($encA32) !== 4 && \count($encA32) !== 8) {
            throw new CryptoException(\sprintf(
                'Unexpected node key length %d after decoding; expected 4 or 8 words.',
                \count($encA32)
            ));
        }

        return Aes::decryptKey($masterKeyStr, $encA32);
    }

    /**
     * Generate a fresh random 8-element a32 file node key.
     *
     * Full layout: [aes0^iv0, aes1^iv1, aes2^mac0, aes3^mac1, iv0, iv1, mac0, mac1]
     * Initially mac0=mac1=0 (the Uploader writes the file MAC back into the key).
     *
     * @return array<int>
     */
    public static function generateNodeKey(): array
    {
        $aes = [
            \random_int(0, 0x7FFFFFFF),
            \random_int(0, 0x7FFFFFFF),
            \random_int(0, 0x7FFFFFFF),
            \random_int(0, 0x7FFFFFFF),
        ];
        $iv = [
            \random_int(0, 0x7FFFFFFF),
            \random_int(0, 0x7FFFFFFF),
        ];

        return [
            $aes[0] ^ $iv[0],
            $aes[1] ^ $iv[1],
            $aes[2],
            $aes[3],
            $iv[0],
            $iv[1],
            0,
            0,
        ];
    }
}
