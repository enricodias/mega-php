<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Exception\CryptoException;
use PHPUnit\Framework\TestCase;

class AttrTest extends TestCase
{
    /**
     * 8-element file node key used across all test cases.
     *
     * @return array<int>
     */
    private function nodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    /**
     * 4-element folder node key.
     *
     * @return array<int>
     */
    private function folderNodeKey(): array
    {
        return [0xdeadbeef, 0xcafebabe, 0x01234567, 0x89abcdef];
    }

    public function testEncryptDecryptRoundtripWithEightWordKey(): void
    {
        $attrs = ['n' => 'photo.jpg', 'extra' => 'value'];

        $ciphertext = Attr::encrypt($attrs, $this->nodeKey());
        $decoded = Attr::decrypt($ciphertext, $this->nodeKey());

        $this->assertSame('photo.jpg', $decoded['n']);
        $this->assertSame('value', $decoded['extra']);
    }

    public function testEncryptDecryptRoundtripWithFourWordKey(): void
    {
        $attrs = ['n' => 'document.pdf'];

        $ciphertext = Attr::encrypt($attrs, $this->folderNodeKey());
        $decoded = Attr::decrypt($ciphertext, $this->folderNodeKey());

        $this->assertSame('document.pdf', $decoded['n']);
    }

    public function testDecryptThrowsOnWrongKey(): void
    {
        $ciphertext = Attr::encrypt(['n' => 'secret.txt'], $this->nodeKey());
        $wrongKey = [0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff];

        $this->expectException(CryptoException::class);

        Attr::decrypt($ciphertext, $wrongKey);
    }

    public function testDecryptProducedByManualAesCbc(): void
    {
        // Build ciphertext manually to confirm Attr::decrypt handles the MEGA canary correctly.
        $nodeKey = $this->nodeKey();
        $aesKey = [
            $nodeKey[0] ^ $nodeKey[4],
            $nodeKey[1] ^ $nodeKey[5],
            $nodeKey[2] ^ $nodeKey[6],
            $nodeKey[3] ^ $nodeKey[7],
        ];
        $aesKeyStr = A32::toString($aesKey);
        $json = \json_encode(['n' => 'manual.txt']);
        $plain = 'MEGA' . $json;
        $pad = 16 - (\strlen($plain) % 16);

        if ($pad < 16) {
            $plain .= \str_repeat("\0", $pad);
        }

        $ciphertext = Aes::encryptCbc($aesKeyStr, $plain);

        $decoded = Attr::decrypt($ciphertext, $nodeKey);

        $this->assertSame('manual.txt', $decoded['n']);
    }

    public function testEncryptedBlockIsMultipleOf16Bytes(): void
    {
        $attrs = ['n' => 'file.mp4'];
        $ciphertext = Attr::encrypt($attrs, $this->nodeKey());

        $this->assertSame(0, \strlen($ciphertext) % 16);
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function filenameProvider(): array
    {
        return [
            'simple ascii' => [['n' => 'report.pdf']],
            'unicode name' => [['n' => 'Ünïcödé.txt']],
            'empty name'   => [['n' => '']],
            'extra fields' => [['n' => 'data.csv', 'mtime' => 1700000000]],
        ];
    }

    /**
     * @dataProvider filenameProvider
     *
     * @param array<string, mixed> $attrs
     */
    public function testEncryptDecryptPreservesAttributes(array $attrs): void
    {
        $ciphertext = Attr::encrypt($attrs, $this->nodeKey());
        $decoded = Attr::decrypt($ciphertext, $this->nodeKey());

        foreach ($attrs as $key => $value) {
            $this->assertSame($value, $decoded[$key]);
        }
    }
}
