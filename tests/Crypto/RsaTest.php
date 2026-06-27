<?php

declare(strict_types=1);

namespace Mega\Tests\Crypto;

use Mega\Crypto\Rsa;
use Mega\Exception\AuthException;
use PHPUnit\Framework\TestCase;

class RsaTest extends TestCase
{
    /**
     * decomposeMpiPrivateKey must throw when the blob is too short to read the
     * two-byte bit-length prefix of any component.
     */
    public function testDecomposeMpiPrivateKeyThrowsOnTruncatedInput(): void
    {
        $this->expectException(AuthException::class);

        Rsa::decomposeMpiPrivateKey("\x00");
    }

    /**
     * decomposeMpiPrivateKey must throw when the blob runs out of bytes while
     * reading a subsequent MPI component.
     *
     * We craft a blob that satisfies the first component but is then truncated.
     *
     * MPI encoding: 2-byte big-endian bit-length, followed by ceil(bits/8) bytes.
     * A 1-bit integer encodes as: \x00\x01 (bit-length) + \x01 (1 byte payload).
     */
    public function testDecomposeMpiPrivateKeyThrowsOnTruncatedSecondComponent(): void
    {
        // First valid MPI (1-bit integer = 3 bytes total), then nothing.
        $blob = "\x00\x01\x01";

        $this->expectException(AuthException::class);

        Rsa::decomposeMpiPrivateKey($blob);
    }
}
