<?php

declare(strict_types=1);

namespace Mega\Service;

use Mega\Exception\ApiException;
use Mega\Exception\HttpException;
use Mega\Transport\Connector;

/**
 * Handles node deletion and moves for authenticated MEGA nodes.
 */
class NodeManagementService
{
    /**
     * @var Connector
     */
    private $connector;

    public function __construct(Connector $connector)
    {
        $this->connector = $connector;
    }

    /**
     * Delete a node by handle, including all sub-nodes.
     *
     * @throws ApiException
     * @throws HttpException
     * @throws \InvalidArgumentException
     */
    public function delete(string $handle): void
    {
        if ($handle === '') {
            throw new \InvalidArgumentException('$handle must not be empty.');
        }

        $this->connector->send([
            'a' => 'd',
            'n' => $handle,
        ]);
    }

    /**
     * Move a node to a new parent.
     *
     * @throws ApiException
     * @throws HttpException
     * @throws \InvalidArgumentException
     */
    public function move(string $handle, string $parentHandle): void
    {
        if ($handle === '') {
            throw new \InvalidArgumentException('$handle must not be empty.');
        }

        if ($parentHandle === '') {
            throw new \InvalidArgumentException('$parentHandle must not be empty.');
        }

        $this->connector->send([
            'a' => 'm',
            'n' => $handle,
            't' => $parentHandle,
        ]);
    }
}
