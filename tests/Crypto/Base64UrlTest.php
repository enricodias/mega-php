<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\Base64Url;
use PHPUnit\Framework\TestCase;

class Base64UrlTest extends TestCase
{
    /**
     * Each pair is [raw binary, base64url encoded].
     * Lengths are chosen to cover all three padding cases (0, 1, 2 remainder bytes).
     *
     * @return array<string, array<string>>
     */
    public function encodeDecodeProvider(): array
    {
        return [
            'empty string'                  => ['', ''],
            'three bytes (no padding)'      => ["\xfb\xfc\xfd", '-_z9'],
            'six bytes (no padding)'        => ["\xfb\xfc\xfd\xfe\xff\x00", '-_z9_v8A'],
            'four bytes (one padding byte)' => ["\xfb\xfc\xfd\xfe", '-_z9_g'],
            'one byte (two padding bytes)'  => ["\xfb", '-w'],
            '16 bytes (typical master key)' => [
                "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
                'AQIDBAUGBwgJCgsMDQ4PEA',
            ],
        ];
    }

    /**
     * @dataProvider encodeDecodeProvider
     */
    public function testEncodeProducesExpectedOutput(string $binary, string $encoded): void
    {
        $this->assertSame($encoded, Base64Url::encode($binary));
    }

    /**
     * @dataProvider encodeDecodeProvider
     */
    public function testDecodeProducesExpectedOutput(string $binary, string $encoded): void
    {
        $this->assertSame($binary, Base64Url::decode($encoded));
    }

    public function testDecodeAcceptsCommaAsSlashAlias(): void
    {
        // '_z9' decodes to \xfb\xfc\xfd; ',z9' uses ',' as an alias for '/'
        // (which '_' also maps to), so both must produce identical bytes.
        $withUnderscore = Base64Url::decode('_z9');
        $withComma = Base64Url::decode(',z9');

        $this->assertSame($withUnderscore, $withComma);
    }

    public function testEncodeOutputContainsNoPaddingOrStandardChars(): void
    {
        $encoded = Base64Url::encode(\str_repeat("\xff", 100));

        $this->assertStringNotContainsString('=', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }

    public function testRoundtrip(): void
    {
        $binary = \random_bytes(64);

        $this->assertSame($binary, Base64Url::decode(Base64Url::encode($binary)));
    }
}
