<?php

declare(strict_types=1);

namespace Mega\Entity;

/**
 * Represents a file or folder node in the MEGA filesystem.
 */
class Node
{
    /**
     * Node type constant for a file.
     */
    const TYPE_FILE = 0;

    /**
     * Node type constant for a folder.
     */
    const TYPE_FOLDER = 1;

    /**
     * @var string
     */
    private $handle;

    /**
     * @var int
     */
    private $type;

    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $encryptedKey;

    public function __construct(string $handle, int $type, string $name, string $encryptedKey)
    {
        $this->handle = $handle;
        $this->type = $type;
        $this->name = $name;
        $this->encryptedKey = $encryptedKey;
    }

    public function getHandle(): string
    {
        return $this->handle;
    }

    public function getType(): int
    {
        return $this->type;
    }

    public function getName(): string
    {
        return $this->name;
    }

    public function getEncryptedKey(): string
    {
        return $this->encryptedKey;
    }
}
