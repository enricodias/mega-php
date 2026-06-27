<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\Aes;
use PHPUnit\Framework\TestCase;

class AesTest extends TestCase
{
    /**
     * NIST FIPS 197 Appendix B test vector.
     *
     * Key:        2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c
     * Plaintext:  32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34
     * Ciphertext: 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32
     *
     * Because our CBC uses a zero IV, the first (and only) block of a
     * single-block input is XOR-ed with 0x00...00, which is a no-op.
     * The result is therefore identical to AES-128-ECB for a single block.
     */
    public function testEncryptCbcNistVector(): void
    {
        $key = (string) \hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $plaintext = (string) \hex2bin('3243f6a8885a308d313198a2e0370734');
        $ciphertext = (string) \hex2bin('3925841d02dc09fbdc118597196a0b32');

        $this->assertSame($ciphertext, Aes::encryptCbc($key, $plaintext));
    }

    public function testDecryptCbcNistVector(): void
    {
        $key = (string) \hex2bin('2b7e151628aed2a6abf7158809cf4f3c');
        $plaintext = (string) \hex2bin('3243f6a8885a308d313198a2e0370734');
        $ciphertext = (string) \hex2bin('3925841d02dc09fbdc118597196a0b32');

        $this->assertSame($plaintext, Aes::decryptCbc($key, $ciphertext));
    }

    public function testEncryptDecryptRoundtrip(): void
    {
        $key = \random_bytes(16);
        $data = \random_bytes(32);

        $this->assertSame($data, Aes::decryptCbc($key, Aes::encryptCbc($key, $data)));
    }

    /**
     * decryptKey with a 4-element a32 array must be the inverse of a single
     * AES-CBC encryption. We verify this by encrypting a known block and then
     * confirming decryptKey recovers the original.
     */
    public function testDecryptKeyFourElements(): void
    {
        $key = \str_repeat("\x2b\x7e\x15\x16", 4);
        $original = [0x3243F6A8, 0x885A308D, 0x313198A2, 0xE0370734];

        $cipherBin = Aes::encryptCbc($key, (string) \pack('N*', ...$original));
        $cipherA32 = \array_values((array) \unpack('N*', $cipherBin));
        $decrypted = Aes::decryptKey($key, $cipherA32);

        $this->assertSame($original, $decrypted);
    }

    public function testDecryptKeyEightElements(): void
    {
        $key = \str_repeat("\x2b\x7e\x15\x16", 4);
        $original = [0x00010203, 0x04050607, 0x08090A0B, 0x0C0D0E0F,
                     0x10111213, 0x14151617, 0x18191A1B, 0x1C1D1E1F];

        $cipherBin = '';
        for ($i = 0; $i < 8; $i += 4) {
            $cipherBin .= Aes::encryptCbc($key, (string) \pack('N*', ...\array_slice($original, $i, 4)));
        }
        $cipherA32 = \array_values((array) \unpack('N*', $cipherBin));
        $decrypted = Aes::decryptKey($key, $cipherA32);

        $this->assertSame($original, $decrypted);
    }

    public function testDeriveKeyFromPasswordKnownVector(): void
    {
        $result = Aes::deriveKeyFromPassword('test-password');

        $this->assertSame('715be4256ee96e09caa85ae18f6e3b7d', \bin2hex($result));
    }

    public function testUserHashKnownVector(): void
    {
        $key = Aes::deriveKeyFromPassword('test-password');
        $result = Aes::userHash('user@example.com', $key);

        $this->assertSame('HyV6oXC4iK8', $result);
    }
}
