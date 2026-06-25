<?php

declare(strict_types=1);

namespace Mega;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * MEGA API client.
 */
class Client
{
    /**
     * @var Config
     */
    private $config;

    /**
     * @var LoggerInterface
     */
    private $logger;

    public function __construct(Config $config = null, LoggerInterface $logger = null)
    {
        $this->config = $config !== null ? $config : new Config();
        $this->logger = $logger !== null ? $logger : new NullLogger();
    }

    /**
     * Authenticate using email and password.
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function login(string $email, string $password): Entity\Session
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Restore a previously exported session.
     *
     * @throws \Mega\Exception\AuthException
     */
    public function restoreSession(Entity\Session $session): void
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Export the current session for later restoration.
     *
     * @throws \Mega\Exception\AuthException
     */
    public function exportSession(): Entity\Session
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Retrieve metadata for a public file link without authentication.
     *
     * @throws \Mega\Exception\InvalidLinkException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function getPublicFileInfo(string $link): Entity\FileInfo
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Download a public file. Returns file content as a string when $destination is null,
     * or the number of bytes written when a stream resource is given.
     *
     * @param string        $link
     * @param resource|null $destination
     *
     * @return string|int
     *
     * @throws \Mega\Exception\InvalidLinkException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     * @throws \Mega\Exception\CryptoException
     */
    public function downloadPublicFile(string $link, $destination = null)
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * List all nodes in the authenticated user's filesystem.
     *
     * @return Entity\Node[]
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function listNodes(): array
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Retrieve metadata for an authenticated node.
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function getFileInfo(Entity\Node $node): Entity\FileInfo
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Download an authenticated file. Returns file content as a string when $destination is null,
     * or the number of bytes written when a stream resource is given.
     *
     * @param Entity\Node $node
     * @param resource|null    $destination
     *
     * @return string|int
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     * @throws \Mega\Exception\CryptoException
     */
    public function downloadFile(Entity\Node $node, $destination = null)
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Upload a file to the given parent node.
     *
     * @param string|resource $source
     * @param string          $parentHandle
     * @param string|null     $name
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     * @throws \Mega\Exception\CryptoException
     */
    public function uploadFile($source, string $parentHandle, string $name = null): Entity\TransferResult
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Delete a node by handle, including all sub-nodes.
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function deleteNode(string $handle): void
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Move a node to a new parent.
     *
     * @throws \Mega\Exception\AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function moveNode(string $handle, string $parentHandle): Entity\Node
    {
        throw new \BadMethodCallException('Not implemented');
    }
}
