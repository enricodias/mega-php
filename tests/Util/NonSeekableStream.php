<?php

declare(strict_types=1);

namespace Mega\Tests\Util;

/**
 * Minimal stream wrapper used to exercise a genuinely non-seekable stream in
 * tests. Deliberately omits stream_seek(), so fseek() on it fails at
 * runtime. Note that stream_get_meta_data() still reports 'seekable' => true
 * for userspace wrappers regardless, which is exactly why
 * NodeService::measureSeekableStream() checks fseek()'s return value rather
 * than trusting that metadata flag.
 */
class NonSeekableStream
{
    /**
     * @var resource|null
     */
    public $context;

    /**
     * @var string
     */
    private static $content = '';

    /**
     * @var int
     */
    private $position = 0;

    public static function setContent(string $content): void
    {
        self::$content = $content;
    }

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $this->position = 0;

        return true;
    }

    public function stream_read(int $count): string
    {
        $chunk = \substr(self::$content, $this->position, $count);
        $this->position += \strlen($chunk);

        return $chunk;
    }

    public function stream_eof(): bool
    {
        return $this->position >= \strlen(self::$content);
    }

    /**
     * @return array<int|string, int>
     */
    public function stream_stat(): array
    {
        return [];
    }
}
