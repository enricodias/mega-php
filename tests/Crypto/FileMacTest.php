<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\FileMac;
use Mega\Crypto\NodeKey;
use PHPUnit\Framework\TestCase;

class FileMacTest extends TestCase
{
    /**
     * Fixed 8-element a32 node key used for all tests.
     *
     * @return array<int>
     */
    private function nodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    public function testFileMacWithNoChunksReturnsZeroArray(): void
    {
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));

        $result = FileMac::fileMac([], $aesKey);

        $this->assertSame([0, 0, 0, 0], $result);
    }

    public function testFileMacWithSingleChunkMatchesDirectEncryption(): void
    {
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));

        // Chunk MAC is a 4-element a32 value
        $chunkMac = [0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00];

        // fileMac with one chunk: XOR initial [0,0,0,0] with chunkMac, then AES-CBC encrypt
        $xored = A32::toString($chunkMac);
        $expected = A32::fromString(Aes::encryptCbc($aesKey, $xored));

        $result = FileMac::fileMac([$chunkMac], $aesKey);

        $this->assertSame($expected, $result);
    }

    public function testFileMacWithTwoChunksAppliesFoldingTwice(): void
    {
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));

        $chunk1 = [0xAAAAAAAA, 0xBBBBBBBB, 0xCCCCCCCC, 0xDDDDDDDD];
        $chunk2 = [0x11111111, 0x22222222, 0x33333333, 0x44444444];

        // First fold
        $xored1 = A32::toString($chunk1); // XOR with [0,0,0,0]
        $mac1 = A32::fromString(Aes::encryptCbc($aesKey, $xored1));

        // Second fold
        $xored2 = A32::toString([
            $mac1[0] ^ $chunk2[0],
            $mac1[1] ^ $chunk2[1],
            $mac1[2] ^ $chunk2[2],
            $mac1[3] ^ $chunk2[3],
        ]);
        $expected = A32::fromString(Aes::encryptCbc($aesKey, $xored2));

        $result = FileMac::fileMac([$chunk1, $chunk2], $aesKey);

        $this->assertSame($expected, $result);
    }

    public function testChunkMacKnownOutput(): void
    {
        $nodeKey = $this->nodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));

        // computed manually
        $expected = [
            3147235931,
            211676832,
            2451044490,
            3181444132,
        ];

        $result = FileMac::chunkMac(str_repeat("A", 16), $aesKey, $nodeKey);

        $this->assertSame($expected, $result);
    }
}
