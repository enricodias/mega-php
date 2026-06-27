<?php

declare(strict_types=1);

namespace Mega\Crypto;

use Mega\Exception\AuthException;

/**
 * RSA private-key decryption using bcmath.
 *
 * Port of the Crypt_RSA-derived code in MEGA's legacy megaAPI.class.php,
 * which itself originates from the PEAR Crypt_RSA package.
 */
class Rsa
{
    /**
     * Decrypt RSA-encrypted data using the private key components (p, q, d).
     *
     * @param string $encData bcmath integer string of the ciphertext
     * @param string $p       bcmath prime p
     * @param string $q       bcmath prime q
     * @param string $d       bcmath private exponent d
     *
     * @return string Raw binary plaintext
     */
    public static function decrypt(string $encData, string $p, string $q, string $d): string
    {
        $modulus = \bcmul($p, $q);
        $encBin = self::intToBin($encData);
        $dataLen = \strlen($encBin);
        $chunkLen = self::bitLen($modulus) - 1;
        $blockLen = (int) \ceil($chunkLen / 8);
        $currPos = 0;
        $bitPos = 0;
        $plain = '0';

        while ($currPos < $dataLen) {
            $chunk = self::binToInt(\substr($encBin, $currPos, $blockLen));
            $chunk = \bcpowmod($chunk, $d, $modulus);
            $plain = self::bitOr($plain, $chunk, $bitPos);
            $bitPos += $chunkLen;
            $currPos += $blockLen;
        }

        return self::intToBin($plain);
    }

    /**
     * Break a DER-style private key blob into four MPI bcmath integer strings.
     *
     * The four components are p, q, d, u in MEGA's key format.
     *
     * @return array<int, string> Four bcmath integer strings: [p, q, d, u]
     *
     * @throws AuthException
     */
    public static function decomposeMpiPrivateKey(string $privkStr): array
    {
        $components = [];
        for ($i = 0; $i < 4; $i++) {
            if (\strlen($privkStr) < 2) {
                throw new AuthException('Private key data truncated while reading MPI component ' . $i . '.');
            }
            $byteLen = ((\ord($privkStr[0]) * 256 + \ord($privkStr[1]) + 7) >> 3) + 2;
            $components[$i] = A32::mpiToInt(\substr($privkStr, 0, $byteLen));
            $privkStr = \substr($privkStr, $byteLen);
        }

        return $components;
    }

    /**
     * Convert a raw big-endian byte string to a bcmath integer string.
     *
     * @param string $str Raw binary input
     *
     * @return string bcmath integer string
     */
    private static function binToInt(string $str): string
    {
        $result = '0';
        $n = \strlen($str);

        for ($i = 0; $i < $n; $i++) {
            $result = \bcadd(\bcmul($result, '256'), (string) \ord($str[$i]));
        }

        return $result;
    }

    /**
     * Convert a bcmath integer string to a raw big-endian byte string.
     *
     * @param string $num bcmath integer string
     *
     * @return string Raw binary output
     */
    private static function intToBin(string $num): string
    {
        $result = '';
        do {
            $result = \chr((int) \bcmod($num, '256')) . $result;
            $num = \bcdiv($num, '256');
        } while (\bccomp($num, '0') > 0);

        return $result;
    }

    /**
     * Return the number of significant bits in a bcmath integer.
     *
     * @param string $num bcmath integer string
     *
     * @return int Bit length
     */
    private static function bitLen(string $num): int
    {
        $bin = self::intToBin($num);
        $bitLen = \strlen($bin) * 8;
        $last = \ord($bin[\strlen($bin) - 1]);

        if ($last === 0) {
            return $bitLen - 8;
        }

        while (!($last & 0x80)) {
            $bitLen--;
            $last <<= 1;
        }

        return $bitLen;
    }

    /**
     * Bitwise OR two bcmath integers, aligning $num2 to a bit offset within $num1.
     *
     * Used during RSA decryption to accumulate plaintext chunks at their correct
     * bit positions in the output integer.
     *
     * @param string $num1     bcmath integer string (accumulator)
     * @param string $num2     bcmath integer string (chunk to merge)
     * @param int    $startPos Bit offset at which $num2 is placed into $num1
     *
     * @return string bcmath integer string with $num2 OR-ed into $num1 at $startPos
     */
    private static function bitOr(string $num1, string $num2, int $startPos): string
    {
        $startByte = (int) ($startPos / 8);
        $startBit = $startPos % 8;
        $tmp1 = self::intToBin($num1);
        $num2 = \bcmul($num2, (string) (1 << $startBit));
        $tmp2 = self::intToBin($num2);

        if ($startByte >= \strlen($tmp1)) {
            return self::binToInt(\str_pad($tmp1, $startByte, "\0") . $tmp2);
        }

        $overlap = \substr($tmp1, $startByte);
        $combined = $tmp2 | $overlap;
        $tmp1 = \substr($tmp1, 0, $startByte) . $combined;

        return self::binToInt($tmp1);
    }
}
