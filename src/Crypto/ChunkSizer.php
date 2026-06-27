<?php

declare(strict_types=1);

namespace Mega\Crypto;

/**
 * Computes MEGA's chunk boundary map and the corresponding AES-CTR IV for
 * each chunk.
 *
 * MEGA uses a non-uniform chunk schedule: the first eight chunks grow
 * linearly (128 KB, 256 KB, ..., 1 MB) and all subsequent chunks are 1 MB.
 * The final chunk is trimmed to the remaining file length.
 */
class ChunkSizer
{
    /**
     * Build the chunk map for a file of the given size.
     *
     * Returns an array keyed by the byte offset of each chunk, with the chunk
     * size in bytes as the value. The map is ordered by offset (ascending).
     *
     * @return array<int, int> [offset => chunkSize]
     */
    public static function getChunks(int $size): array
    {
        if ($size === 0) {
            return [];
        }

        $chunks = [];
        $p = 0;
        $pp = 0;

        for ($i = 1; $i <= 8 && $p < $size - $i * 0x20000; $i++) {
            $chunks[$p] = $i * 0x20000;
            $pp = $p;
            $p += $chunks[$p];
        }

        while ($p < $size) {
            $chunks[$p] = 0x100000;
            $pp = $p;
            $p += $chunks[$p];
        }

        // Trim the last chunk to the actual remaining length
        $chunks[$pp] = $size - $pp;
        if ($chunks[$pp] === 0) {
            unset($chunks[$pp]);
        }

        return $chunks;
    }

    /**
     * Advance the AES-CTR IV by the given number of encrypted bytes.
     *
     * MEGA's CTR counter occupies the last two 32-bit words of the 16-byte IV
     * and is incremented by one per 16-byte AES block. Any partial block still
     * advances the counter by one (ceiling division).
     *
     * @param string $iv    16-byte binary IV
     * @param int    $bytes Number of bytes consumed in the previous chunk
     *
     * @return string 16-byte updated IV
     */
    public static function incrementIv(string $iv, int $bytes): string
    {
        $blocks = (int) \ceil($bytes / 16);

        $words = \array_values((array) \unpack('N4', $iv));

        $carry = $blocks;
        for ($i = 3; $i >= 2 && $carry > 0; $i--) {
            $sum = $words[$i] + $carry;
            $words[$i] = $sum & 0xFFFFFFFF;
            $carry = $sum >> 32;
        }

        return (string) \pack('N4', $words[0], $words[1], $words[2], $words[3]);
    }

    /**
     * Build the initial AES-CTR IV from an 8-element file node key.
     *
     * The IV is words 4 and 5 of the node key followed by two zero words.
     *
     * @param array<int> $nodeKey 8-element a32 file node key
     *
     * @return string 16-byte binary IV
     */
    public static function ivFromNodeKey(array $nodeKey): string
    {
        return A32::toString([$nodeKey[4], $nodeKey[5], 0, 0]);
    }
}
