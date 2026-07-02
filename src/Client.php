<?php

declare(strict_types=1);

namespace Mega;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Exception\InvalidLinkException;
use Mega\Service\NodeManagementService;
use Mega\Service\NodeService;
use Mega\Service\PublicFileService;
use Mega\Service\SessionAuthenticator;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\SessionCache;
use Mega\Transport\Uploader;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * MEGA API client.
 */
class Client
{
    /**
     * @var Connector
     */
    private $connector;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var SessionCache|null
     */
    private $sessionCache;

    /**
     * @var Session|null
     */
    private $session;

    /**
     * @var SessionAuthenticator
     */
    private $sessionAuthenticator;

    /**
     * @var NodeManagementService
     */
    private $nodeManagementService;

    /**
     * @var PublicFileService
     */
    private $publicFileService;

    /**
     * @var NodeService
     */
    private $nodeService;

    public function __construct(
        Connector $connector,
        Downloader $downloader,
        Uploader $uploader,
        ?LoggerInterface $logger = null,
        ?SessionCache $sessionCache = null,
        ?SessionAuthenticator $sessionAuthenticator = null,
        ?NodeManagementService $nodeManagementService = null,
        ?PublicFileService $publicFileService = null,
        ?NodeService $nodeService = null
    ) {
        $this->connector = $connector;
        $this->logger = $logger !== null ? $logger : new NullLogger();
        $this->sessionCache = $sessionCache;
        $this->session = null;
        $this->sessionAuthenticator = $sessionAuthenticator !== null ? $sessionAuthenticator : new SessionAuthenticator();
        $this->nodeManagementService = $nodeManagementService !== null ? $nodeManagementService : new NodeManagementService($connector);
        $this->publicFileService = $publicFileService !== null ? $publicFileService : new PublicFileService($connector, $downloader);
        $this->nodeService = $nodeService !== null ? $nodeService : new NodeService($connector, $downloader, $uploader, $this->logger);
    }

    /**
     * Authenticate using email and password.
     *
     * When a PSR-6 cache pool was provided to the factory, a cached session is
     * returned on a hit, avoiding a round-trip to the MEGA API.
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     */
    public function login(string $email, string $password): Session
    {
        if ($this->sessionCache !== null) {
            $cached = $this->sessionCache->get($email);
            if ($cached !== null) {
                $this->logger->info('Restored MEGA session from cache', ['email' => $email]);
                $this->applySession($cached);
                return $cached;
            }
        }

        $this->logger->info('Logging in to MEGA', ['email' => $email]);

        $passwordKey = Aes::deriveKeyFromPassword($password);
        $userHash    = Aes::userHash(\strtolower($email), $passwordKey);

        $response = $this->connector->send([
            'a'    => 'us',
            'user' => $email,
            'uh'   => $userHash,
        ]);

        $session = $this->sessionAuthenticator->buildSessionFromLoginResponse($response, $passwordKey);

        if ($this->sessionCache !== null) {
            $this->sessionCache->set($email, $session);
        }

        $this->applySession($session);

        return $session;
    }

    /**
     * Restore a previously exported session without re-authenticating.
     */
    public function restoreSession(Session $session): void
    {
        $this->applySession($session);
    }

    /**
     * Export the current active session.
     *
     * @throws AuthException
     */
    public function exportSession(): Session
    {
        $this->requireSession();

        return $this->session;
    }

    /**
     * Retrieve metadata for a public file link without authentication.
     *
     * @throws InvalidLinkException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function getPublicFileInfo(string $link): FileInfo
    {
        $this->logger->info('Requesting public file info', ['link' => $link]);

        return $this->publicFileService->getFileInfo($link);
    }

    /**
     * Download a public file. Returns decrypted file content as a string when
     * $destination is null, or the number of bytes written when a writable
     * stream resource is given.
     *
     * @param string        $link
     * @param resource|null $destination
     *
     * @return string|int
     *
     * @throws InvalidLinkException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function downloadPublicFile(string $link, $destination = null)
    {
        $this->logger->info('Downloading public file', ['link' => $link]);

        return $this->publicFileService->download($link, $destination);
    }

    /**
     * List all nodes in the authenticated user's filesystem.
     *
     * Returns file and folder nodes with decrypted names. Nodes whose keys
     * cannot be decrypted are silently skipped.
     *
     * @return Node[]
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     */
    public function listNodes(): array
    {
        $this->requireSession();

        $this->logger->info('Listing MEGA nodes');

        $masterKeyStr = A32::toString($this->session->getMasterKey());

        return $this->nodeService->listNodes($masterKeyStr);
    }

    /**
     * Retrieve metadata for an authenticated node.
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function getFileInfo(Node $node): FileInfo
    {
        $this->requireSession();

        $this->logger->info('Requesting file info', ['handle' => $node->getHandle()]);

        $masterKeyStr = A32::toString($this->session->getMasterKey());

        return $this->nodeService->getFileInfo($node, $masterKeyStr);
    }

    /**
     * Download an authenticated file. Returns decrypted file content as a
     * string when $destination is null, or the number of bytes written when a
     * writable stream resource is given.
     *
     * @param Node          $node
     * @param resource|null $destination
     *
     * @return string|int
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function downloadFile(Node $node, $destination = null)
    {
        $this->requireSession();

        $this->logger->info('Downloading file', ['handle' => $node->getHandle()]);

        $masterKeyStr = A32::toString($this->session->getMasterKey());

        return $this->nodeService->download($node, $masterKeyStr, $destination);
    }

    /**
     * Upload a file to the given parent node.
     *
     * $source may be a readable stream resource or a local file path string.
     * If $name is null and $source is a path, the basename of the path is used.
     * If $name is null and $source is a stream, a unique name is generated
     * with the format 'upload_<unique id>' and the event is logged.
     *
     * @param string|resource $source
     * @param string          $parentHandle
     * @param string|null     $name
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     * @throws \InvalidArgumentException
     */
    public function uploadFile($source, string $parentHandle = '', ?string $name = null): Node
    {
        $this->requireSession();

        $this->logger->info('Uploading file', ['name' => $name, 'parent' => $parentHandle]);

        $masterKeyStr = A32::toString($this->session->getMasterKey());

        return $this->nodeService->upload($source, $parentHandle, $masterKeyStr, $name);
    }

    /**
     * Delete a node by handle, including all sub-nodes.
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     * @throws \InvalidArgumentException
     */
    public function deleteNode(string $handle): void
    {
        $this->requireSession();

        $this->logger->info('Deleting node', ['handle' => $handle]);

        $this->nodeManagementService->delete($handle);
    }

    /**
     * Move a node to a new parent.
     *
     * @throws AuthException
     * @throws ApiException
     * @throws HttpException
     * @throws \InvalidArgumentException
     */
    public function moveNode(string $handle, string $parentHandle): void
    {
        $this->requireSession();

        $this->logger->info('Moving node', ['handle' => $handle, 'parent' => $parentHandle]);

        $this->nodeManagementService->move($handle, $parentHandle);
    }

    /**
     * @throws AuthException
     */
    private function requireSession(): void
    {
        if ($this->session === null) {
            throw new AuthException('No active session. Call login() or restoreSession() first.');
        }
    }

    private function applySession(Session $session): void
    {
        $this->session = $session;
        $this->connector->setSessionId($session->getSessionId());
    }
}
