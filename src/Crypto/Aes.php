<?php

declare(strict_types=1);

namespace Mega\Crypto;

/**
 * AES-128-CBC helpers and MEGA-specific key derivation / hashing.
 *
 * All AES operations use a zero IV and no standard padding (OPENSSL_ZERO_PADDING),
 * matching MEGA's Javascript crypto_2.js behaviour.
 */
class Aes
{
    /**
     * AES-128-CBC encrypt with zero IV.
     *
     * @param string $key  16-byte key
     * @param string $data Plaintext (length must be a multiple of 16)
     *
     * @return string Ciphertext
     */
    public static function encryptCbc(string $key, string $data): string
    {
        return (string) \openssl_encrypt(
            $data,
            'aes-128-cbc',
            $key,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            \str_repeat("\0", 16)
        );
    }

    /**
     * AES-128-CBC decrypt with zero IV.
     *
     * @param string $key  16-byte key
     * @param string $data Ciphertext (length must be a multiple of 16)
     *
     * @return string Plaintext
     */
    public static function decryptCbc(string $key, string $data): string
    {
        return (string) \openssl_decrypt(
            $data,
            'aes-128-cbc',
            $key,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            \str_repeat("\0", 16)
        );
    }

    /**
     * Decrypt a 4- or 8-element a32 array with the given string key.
     *
     * An 8-element array is split into two 4-element blocks, each decrypted
     * independently, and the results concatenated.
     *
     * @param string     $key 16-byte key string
     * @param array<int> $a   4 or 8 element a32 array
     *
     * @return array<int>
     */
    public static function decryptKey(string $key, array $a): array
    {
        if (\count($a) === 4) {
            return A32::fromString(self::decryptCbc($key, A32::toString($a)));
        }

        $result = [];
        for ($i = 0; $i < \count($a); $i += 4) {
            $block  = self::decryptCbc($key, A32::toString(\array_slice($a, $i, 4)));
            $result = \array_merge($result, A32::fromString($block));
        }

        return $result;
    }

    /**
     * Derive the 128-bit AES password key from a plaintext password.
     *
     * Port of crypto_2.js prepare_key / prepare_key_pw.
     *
     * @return string 16-byte AES key string
     */
    public static function deriveKeyFromPassword(string $password): string
    {
        $a = A32::fromString($password);
        $pkey = A32::toString([0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56]);
        $total = \count($a);

        for ($r = 65536; $r--;) {
            for ($j = 0; $j < $total; $j += 4) {
                $key = [0, 0, 0, 0];
                for ($i = 0; $i < 4; $i++) {
                    if ($i + $j < $total) {
                        $key[$i] = $a[$i + $j];
                    }
                }
                $pkey = self::encryptCbc(A32::toString($key), $pkey);
            }
        }

        return $pkey;
    }

    /**
     * Compute the user auth hash sent in the 'us' API command.
     *
     * Port of crypto_2.js stringhash.
     *
     * @param string $str    Lowercased email address
     * @param string $aesKey 16-byte AES key (from deriveKeyFromPassword)
     *
     * @return string MEGA base64url-encoded hash
     */
    public static function userHash(string $str, string $aesKey): string
    {
        $s32 = A32::fromString($str);
        $h32 = [0, 0, 0, 0];

        foreach ($s32 as $i => $word) {
            $h32[$i & 3] ^= $word;
        }

        $h32str = A32::toString($h32);

        for ($i = 16384; $i--;) {
            $h32str = self::encryptCbc($aesKey, $h32str);
        }

        $h32 = A32::fromString($h32str);

        return A32::toBase64([$h32[0], $h32[2]]);
    }
}
