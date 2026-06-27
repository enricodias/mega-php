<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\A32;
use PHPUnit\Framework\TestCase;

class A32Test extends TestCase
{
    /**
     * @return array<string, array<mixed>>
     */
    public function fromStringProvider(): array
    {
        return [
            'four bytes, one word'   => ["\x00\x00\x00\x01", [1]],
            'eight bytes, two words' => ["\x00\x00\x00\x01\x00\x00\x00\x02", [1, 2]],
            'big-endian word order'  => ["\x01\x02\x03\x04", [0x01020304]],
            'all 0xFF'               => ["\xff\xff\xff\xff", [0xFFFFFFFF]],
        ];
    }

    /**
     * @dataProvider fromStringProvider
     *
     * @param array<int> $expected
     */
    public function testFromString(string $input, array $expected): void
    {
        $this->assertSame($expected, A32::fromString($input));
    }

    public function testFromStringZeroPadsToWordBoundary(): void
    {
        // Three-byte input -> padded to four bytes -> one word 0x61626300
        $result = A32::fromString('abc');

        $this->assertCount(1, $result);
        $this->assertSame(0x61626300, $result[0]);
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function toStringProvider(): array
    {
        return [
            'single word'     => [[1], "\x00\x00\x00\x01"],
            'two words'       => [[1, 2], "\x00\x00\x00\x01\x00\x00\x00\x02"],
            'big-endian order'=> [[0x01020304], "\x01\x02\x03\x04"],
            'all 0xFF word'   => [[0xFFFFFFFF], "\xff\xff\xff\xff"],
        ];
    }

    /**
     * @dataProvider toStringProvider
     *
     * @param array<int> $input
     */
    public function testToString(array $input, string $expected): void
    {
        $this->assertSame($expected, A32::toString($input));
    }

    public function testFromStringToStringRoundtrip(): void
    {
        $original = "\xde\xad\xbe\xef\xca\xfe\xba\xbe";

        $this->assertSame($original, A32::toString(A32::fromString($original)));
    }

    public function testFromBase64(): void
    {
        // Base64Url::decode("\x00\x00\x00\x01") -> 'AAAAB' in base64url (no padding)
        // Verify round-trip via A32::toBase64
        $words = [0x01020304, 0xDEADBEEF];

        $this->assertSame($words, A32::fromBase64(A32::toBase64($words)));
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function mpiToIntProvider(): array
    {
        return [
            'integer 1 (9 bits, 2 byte payload)' => [
                "\x00\x09\x01",
                // bit-length prefix 0x0009 means 9 bits; value byte 0x01 = 1
                // but mpiToInt reads from index 2 (after the 2-byte prefix)
                // The byte 0x01 encodes integer 1
                '1',
            ],
            'integer 256 (9 bits)' => [
                "\x00\x09\x01\x00",
                '256',
            ],
            'integer 255' => [
                "\x00\x08\xff",
                '255',
            ],
        ];
    }

    /**
     * @dataProvider mpiToIntProvider
     */
    public function testMpiToInt(string $mpi, string $expected): void
    {
        $this->assertSame($expected, A32::mpiToInt($mpi));
    }
}
