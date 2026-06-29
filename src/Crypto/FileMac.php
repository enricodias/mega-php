<?php

declare(strict_types=1);

namespace Mega\Crypto;

/**
 * Computes MEGA's chunk MAC and file MAC values required during upload.
 *
 * Each chunk MAC is a 16-byte value derived by running every 16-byte block
 * of a chunk through AES-CBC with a per-chunk IV (derived from the CTR IV)
 * and the file's AES key. All chunk MACs are then folded together to produce
 * the 16-byte file MAC.
 */
class FileMac
{
    /**
     * Compute the MAC for a single plaintext chunk.
     *
     * The chunk IV is built from the two CTR IV words (words 4 and 5 of the
     * node key) followed by themselves, matching MEGA's JS SDK behaviour.
     *
     * @param string     $plainChunk Raw plaintext chunk bytes
     * @param string     $aesKey     16-byte AES key (XOR-folded from node key)
     * @param array<int> $nodeKey    8-element a32 node key (unfolded)
     *
     * @return array<int> 4-element a32 chunk MAC
     */
    public static function chunkMac(string $plainChunk, string $aesKey, array $nodeKey): array
    {
        $chunkIv = A32::toString([$nodeKey[4], $nodeKey[5], $nodeKey[4], $nodeKey[5]]);

        $mac = $chunkIv;

        $len = \strlen($plainChunk);
        for ($i = 0; $i < $len; $i += 16) {
            $block = \substr($plainChunk, $i, 16);

            if (\strlen($block) < 16) {
                $block = \str_pad($block, 16, "\0");
            }

            $xored = '';
            for ($j = 0; $j < 16; $j++) {
                $xored .= \chr(\ord($mac[$j]) ^ \ord($block[$j]));
            }

            $mac = Aes::encryptCbc($aesKey, $xored);
        }

        return A32::fromString($mac);
    }

    /**
     * Fold an array of chunk MACs into a single file MAC.
     *
     * Each chunk MAC (4-element a32) is XOR'd with the running file MAC
     * words and then encrypted with AES-CBC. The initial value is all zeros.
     *
     * @param array<array<int>> $chunkMacs Array of 4-element a32 chunk MACs
     * @param string            $aesKey    16-byte AES key
     *
     * @return array<int> 4-element a32 file MAC
     */
    public static function fileMac(array $chunkMacs, string $aesKey): array
    {
        $mac = [0, 0, 0, 0];

        foreach ($chunkMacs as $chunkMac) {
            $xored = [
                $mac[0] ^ $chunkMac[0],
                $mac[1] ^ $chunkMac[1],
                $mac[2] ^ $chunkMac[2],
                $mac[3] ^ $chunkMac[3],
            ];

            $mac = A32::fromString(Aes::encryptCbc($aesKey, A32::toString($xored)));
        }

        return $mac;
    }
}
