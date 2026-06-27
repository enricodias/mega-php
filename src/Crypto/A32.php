<?php

declare(strict_types=1);

namespace Mega\Crypto;

/**
 * Conversions between raw byte strings and MEGA's array-of-32-bit-words (a32) format.
 *
 * All integers are big-endian 32-bit unsigned words, matching MEGA's Javascript
 * representation.
 */
class A32
{
    /**
     * Convert a raw byte string to an array of 32-bit unsigned integers.
     *
     * The input is zero-padded to the next 4-byte boundary before unpacking.
     *
     * @return array<int>
     */
    public static function fromString(string $b): array
    {
        $padding = (((\strlen($b) + 3) >> 2) * 4) - \strlen($b);

        if ($padding > 0) {
            $b .= \str_repeat("\0", $padding);
        }

        return \array_values((array) \unpack('N*', $b));
    }

    /**
     * Convert an array of 32-bit unsigned integers to a raw byte string.
     *
     * @param array<int> $a
     */
    public static function toString(array $a): string
    {
        return (string) \call_user_func_array('\pack', \array_merge(['N*'], $a));
    }

    /**
     * Decode a MEGA base64url string and convert it to an a32 array.
     *
     * @return array<int>
     */
    public static function fromBase64(string $s): array
    {
        return self::fromString(Base64Url::decode($s));
    }

    /**
     * Convert an a32 array to a MEGA base64url string.
     *
     * @param array<int> $a
     */
    public static function toBase64(array $a): string
    {
        return Base64Url::encode(self::toString($a));
    }

    /**
     * Decode an MPI (big-endian bit-length-prefixed integer) to a bcmath integer string.
     *
     * The first two bytes encode the bit length; the remaining bytes are the
     * big-endian integer value.
     */
    public static function mpiToInt(string $s): string
    {
        $hex = \bin2hex(\substr($s, 2));
        $len = \strlen($hex);
        $n = '0';

        for ($i = 0; $i < $len; $i++) {
            $n = \bcadd($n, \bcmul((string) \hexdec($hex[$i]), \bcpow('16', (string) ($len - $i - 1))));
        }

        return $n;
    }
}
