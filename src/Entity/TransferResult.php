<?php

declare(strict_types=1);

namespace Mega\Entity;

/**
 * Represents the result of a completed file upload.
 */
class TransferResult
{
    /**
     * @var Node
     */
    private $node;

    public function __construct(Node $node)
    {
        $this->node = $node;
    }

    public function getNode(): Node
    {
        return $this->node;
    }
}
