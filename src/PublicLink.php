<?php

declare(strict_types=1);

namespace Mega;

use Mega\Exception\InvalidLinkException;

/**
 * Parses MEGA public share links into their handle and key components.
 *
 * MEGA supports two link formats:
 *
 *   Legacy: https://mega.nz/#!<handle>!<key>  (file)
 *           https://mega.nz/#F!<handle>!<key> (folder)
 *
 *   Modern: https://mega.nz/file/<handle>#<key>
 *           https://mega.nz/folder/<handle>#<key>
 */
class PublicLink
{
    const TYPE_FILE = 'file';
    const TYPE_FOLDER = 'folder';

    /**
     * @var string
     */
    private $handle;

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $type;

    private function __construct(string $handle, string $key, string $type)
    {
        $this->handle = $handle;
        $this->key = $key;
        $this->type = $type;
    }

    /**
     * Parse a MEGA public link string.
     *
     * @throws InvalidLinkException
     */
    public static function parse(string $link): self
    {
        $fragment = (string) \parse_url($link, PHP_URL_FRAGMENT);

        // Legacy format: #!<handle>!<key> or #F!<handle>!<key>
        if (self::isMegaHost($link) && \preg_match('/^(F?)!([a-zA-Z0-9]+)!([a-zA-Z0-9_,\-]+)/', $fragment, $m)) {
            $type = $m[1] === 'F' ? self::TYPE_FOLDER : self::TYPE_FILE;
            return new self($m[2], $m[3], $type);
        }

        // Modern format: /file/<handle>#<key> or /folder/<handle>#<key>
        if (self::isMegaHost($link) && \preg_match('`/(file|folder)/([a-zA-Z0-9]+)#([a-zA-Z0-9_,\-]+)`', $link, $m)) {
            $type = $m[1] === 'folder' ? self::TYPE_FOLDER : self::TYPE_FILE;
            return new self($m[2], $m[3], $type);
        }

        throw new InvalidLinkException(\sprintf('Cannot parse MEGA link: %s', $link));
    }

    private static function isMegaHost(string $link): bool
    {
        $host = \parse_url($link, PHP_URL_HOST);

        if (!\is_string($host)) {
            return false;
        }

        return $host === 'mega.nz' ||
               $host === 'mega.io' ||
               $host === 'mega.co.nz' ||
               \substr($host, -9) === '.mega.nz' ||
               \substr($host, -9) === '.mega.io' ||
               \substr($host, -12) === '.mega.co.nz';
    }

    public function getHandle(): string
    {
        return $this->handle;
    }

    public function getKey(): string
    {
        return $this->key;
    }

    public function getType(): string
    {
        return $this->type;
    }

    public function isFile(): bool
    {
        return $this->type === self::TYPE_FILE;
    }

    public function isFolder(): bool
    {
        return $this->type === self::TYPE_FOLDER;
    }
}
