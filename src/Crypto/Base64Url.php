<?php

declare(strict_types=1);

namespace Mega\Crypto;

/**
 * MEGA-flavoured base64url encode/decode.
 *
 * MEGA substitutes '+' -> '-', '/' -> '_', strips padding, and also accepts
 * ',' as an alias for '/'. This differs from RFC 4648 base64url only in the
 * comma alias and the specific padding calculation used on decode.
 */
class Base64Url
{
    public static function decode(string $data): string
    {
        $data .= \substr('==', (2 - \strlen($data) * 3) & 3);
        
        return (string) \base64_decode(\str_replace(['-', '_', ','], ['+', '/', '/'], $data));
    }

    public static function encode(string $data): string
    {
        return \str_replace(['+', '/', '='], ['-', '_', ''], \base64_encode($data));
    }
}
