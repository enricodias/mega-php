<?php

declare(strict_types=1);

namespace Mega\Crypto;

use Mega\Exception\CryptoException;

/**
 * Encode and decode MEGA node attribute blocks.
 *
 * Attributes are stored as AES-128-CBC encrypted JSON prefixed with the
 * four-byte canary "MEGA". The key used for CBC is the XOR-folded node key
 * (see NodeKey::foldToAesKey()).
 */
class Attr
{
    private const CANARY = 'MEGA';

    /**
     * Decrypt an attribute block and return its JSON-decoded contents.
     *
     * @param string     $ciphertext Raw (non-base64) ciphertext
     * @param array<int> $nodeKey    4- or 8-element a32 node key
     *
     * @return array<string, mixed>
     *
     * @throws CryptoException
     */
    public static function decrypt(string $ciphertext, array $nodeKey): array
    {
        $aesKey = NodeKey::foldToAesKey($nodeKey);
        $aesKeyStr = A32::toString($aesKey);

        $plain = Aes::decryptCbc($aesKeyStr, $ciphertext);
        $plain = self::depad($plain);

        if (\substr($plain, 0, 4) !== self::CANARY) {
            throw new CryptoException('Attribute block is missing MEGA canary; key may be wrong.');
        }

        $json = \substr($plain, 4);
        $decoded = \json_decode($json, true);

        if (!\is_array($decoded)) {
            // Truncate to the first closing brace and retry
            $brace = \strpos($json, '}');
            if ($brace !== false) {
                $decoded = \json_decode(\substr($json, 0, $brace + 1), true);
            }
        }

        if (!\is_array($decoded)) {
            throw new CryptoException('Failed to JSON-decode decrypted node attributes.');
        }

        return $decoded;
    }

    /**
     * Encode a PHP array as an AES-128-CBC encrypted attribute block.
     *
     * @param array<string, mixed> $attrs
     * @param array<int>           $nodeKey 4- or 8-element a32 node key
     *
     * @return string Encrypted ciphertext (not base64 encoded)
     *
     * @throws CryptoException
     */
    public static function encrypt(array $attrs, array $nodeKey): string
    {
        $json = \json_encode($attrs);

        if ($json === false) {
            throw new CryptoException('Failed to JSON-encode node attributes.');
        }

        $plain = self::CANARY . $json;
        $plain = self::pad($plain);
        $aesKey = NodeKey::foldToAesKey($nodeKey);
        $aesKeyStr = A32::toString($aesKey);

        return Aes::encryptCbc($aesKeyStr, $plain);
    }

    /**
     * Strip trailing null bytes added during AES block padding.
     */
    private static function depad(string $b): string
    {
        $i = \strlen($b);

        while ($i > 0 && \ord($b[$i - 1]) === 0) {
            $i--;
        }

        return \substr($b, 0, $i);
    }

    /**
     * Zero-pad a string to the next AES block boundary (16 bytes).
     */
    private static function pad(string $b): string
    {
        $len = \strlen($b);
        $padding = 16 - ($len % 16);

        if ($padding === 16) {
            return $b;
        }

        return $b . \str_repeat("\0", $padding);
    }
}
