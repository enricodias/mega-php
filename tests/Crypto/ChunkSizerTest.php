<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\A32;
use Mega\Crypto\ChunkSizer;
use PHPUnit\Framework\TestCase;

class ChunkSizerTest extends TestCase
{
    /**
     * @return array<string, array<mixed>>
     */
    public function chunkProvider(): array
    {
        // Each entry: [fileSize, expectedChunks]
        // Chunk boundaries follow: 128KB, 256KB, 384KB, 512KB, 640KB, 768KB, 896KB, 1MB, then 1MB each.
        return [
            'zero bytes' => [
                0,
                [],
            ],
            'one byte' => [
                1,
                [0 => 1],
            ],
            'exactly first chunk boundary (128 KB)' => [
                131072,
                [0 => 131072],
            ],
            'first chunk + small tail' => [
                131072 + 50,
                [0 => 131072, 131072 => 50],
            ],
            'exactly two chunk boundaries (128KB + 256KB = 384KB)' => [
                131072 + 262144,
                [0 => 131072, 131072 => 262144],
            ],
            'small file under first boundary' => [
                1024,
                [0 => 1024],
            ],
        ];
    }

    /**
     * @dataProvider chunkProvider
     *
     * @param array<int, int> $expectedChunks
     */
    public function testGetChunks(int $size, array $expectedChunks): void
    {
        $this->assertSame($expectedChunks, ChunkSizer::getChunks($size));
    }

    public function testChunkSumEqualsFileSize(): void
    {
        foreach ([1, 1024, 131072, 500000, 1048576, 2097152, 5000000] as $size) {
            $chunks = ChunkSizer::getChunks($size);
            $total = \array_sum($chunks);
            $this->assertSame($size, $total, "Chunk sum mismatch for size {$size}");
        }
    }

    public function testChunksAreContiguous(): void
    {
        $size = 3000000;
        $chunks = ChunkSizer::getChunks($size);
        $pos = 0;

        foreach ($chunks as $offset => $chunkSize) {
            $this->assertSame($pos, $offset, "Gap at offset {$pos}");
            $pos += $chunkSize;
        }

        $this->assertSame($size, $pos);
    }

    /**
     * @return array<string, array<mixed>>
     */
    public function incrementIvProvider(): array
    {
        // IV is 16 bytes (4 x uint32 big-endian).
        // Counter occupies words [2] and [3] (indices 2 and 3).
        // incrementIv advances by ceil(bytes / 16) blocks.
        return [
            'one 16-byte block increments counter by 1' => [
                \str_repeat("\x00", 16),
                16,
                // expected: word[3] becomes 1
                \pack('N4', 0, 0, 0, 1),
            ],
            'two 16-byte blocks increments counter by 2' => [
                \str_repeat("\x00", 16),
                32,
                \pack('N4', 0, 0, 0, 2),
            ],
            '17 bytes rounds up to 2 blocks' => [
                \str_repeat("\x00", 16),
                17,
                \pack('N4', 0, 0, 0, 2),
            ],
            'words 0 and 1 are untouched' => [
                \pack('N4', 0xDEADBEEF, 0xCAFEBABE, 0, 0),
                16,
                \pack('N4', 0xDEADBEEF, 0xCAFEBABE, 0, 1),
            ],
        ];
    }

    /**
     * @dataProvider incrementIvProvider
     */
    public function testIncrementIv(string $iv, int $bytes, string $expected): void
    {
        $this->assertSame($expected, ChunkSizer::incrementIv($iv, $bytes));
    }

    public function testIvFromNodeKeyUsesWords4And5(): void
    {
        $nodeKey = [0x00, 0x00, 0x00, 0x00, 0xAABBCCDD, 0x11223344, 0x00, 0x00];
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);

        $words = \array_values((array) \unpack('N4', $iv));

        $this->assertSame(0xAABBCCDD, $words[0]);
        $this->assertSame(0x11223344, $words[1]);
        $this->assertSame(0, $words[2]);
        $this->assertSame(0, $words[3]);
    }
}
