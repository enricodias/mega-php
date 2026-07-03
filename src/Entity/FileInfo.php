<?php

declare(strict_types=1);

namespace Mega\Entity;

/**
 * Holds metadata returned by a file info request.
 */
class FileInfo
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var int
     */
    private $size;

    /**
     * @var string|null
     */
    private $downloadUrl;

    public function __construct(string $name, int $size, ?string $downloadUrl = null)
    {
        $this->name = $name;
        $this->size = $size;
        $this->downloadUrl = $downloadUrl;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    public function getDownloadUrl(): ?string
    {
        return $this->downloadUrl;
    }
}
