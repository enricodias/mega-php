<?php

declare(strict_types=1);

namespace Mega;

use Mega\Crypto\Aes;
use Mega\Crypto\A32;
use Mega\Crypto\Base64Url;
use Mega\Crypto\Rsa;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Entity\TransferResult;
use Mega\Exception\AuthException;
use Mega\Transport\Connector;
use Mega\Transport\SessionCache;
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

    public function __construct(
        Connector $connector,
        ?LoggerInterface $logger = null,
        ?SessionCache $sessionCache = null
    ) {
        $this->connector = $connector;
        $this->logger  = $logger !== null ? $logger : new NullLogger();
        $this->sessionCache = $sessionCache;
        $this->session = null;
    }

    /**
     * Authenticate using email and password.
     *
     * When a PSR-6 cache pool was provided to the factory, a cached session is
     * returned on a hit, avoiding a round-trip to the MEGA API.
     *
     * @throws AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
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

        $session = $this->buildSessionFromLoginResponse($response, $passwordKey);

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
     * @throws \Mega\Exception\InvalidLinkException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function getPublicFileInfo(string $link): FileInfo
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
     * @return Node[]
     *
     * @throws AuthException
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
     * @throws AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function getFileInfo(Node $node): FileInfo
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Download an authenticated file. Returns file content as a string when $destination is null,
     * or the number of bytes written when a stream resource is given.
     *
     * @param Node          $node
     * @param resource|null $destination
     *
     * @return string|int
     *
     * @throws AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     * @throws \Mega\Exception\CryptoException
     */
    public function downloadFile(Node $node, $destination = null)
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
     * @throws AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     * @throws \Mega\Exception\CryptoException
     */
    public function uploadFile($source, string $parentHandle, ?string $name = null): TransferResult
    {
        throw new \BadMethodCallException('Not implemented');
    }

    /**
     * Delete a node by handle, including all sub-nodes.
     *
     * @throws AuthException
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
     * @throws AuthException
     * @throws \Mega\Exception\ApiException
     * @throws \Mega\Exception\HttpException
     */
    public function moveNode(string $handle, string $parentHandle): Node
    {
        throw new \BadMethodCallException('Not implemented');
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

    /**
     * @param array<string, mixed> $response
     *
     * @throws AuthException
     */
    private function buildSessionFromLoginResponse(array $response, string $passwordKey): Session
    {
        if (!\array_key_exists('k', $response)) {
            throw new AuthException('Login response missing master key.');
        }

        $masterKey = A32::fromBase64($response['k']);
        if (\count($masterKey) !== 4) {
            throw new AuthException('Unexpected master key length in login response.');
        }

        $masterKey = Aes::decryptKey($passwordKey, $masterKey);

        if (!\array_key_exists('csid', $response)) {
            throw new AuthException('Login response missing session challenge (csid). Two-factor or alternate login flows are not supported.');
        }

        if (!\array_key_exists('privk', $response)) {
            throw new AuthException('Login response missing private key (privk).');
        }

        $masterKeyStr = A32::toString($masterKey);
        $privkA32  = Aes::decryptKey($masterKeyStr, A32::fromBase64($response['privk']));
        $rsaPrivateKey = Rsa::decomposeMpiPrivateKey(A32::toString($privkA32));

        $csidBytes = Base64Url::decode($response['csid']);
        $csidInt = A32::mpiToInt($csidBytes);
        $sidRaw = Rsa::decrypt($csidInt, $rsaPrivateKey[0], $rsaPrivateKey[1], $rsaPrivateKey[2]);
        $sessionId = Base64Url::encode(\substr(\strrev($sidRaw), 0, 43));

        return new Session($masterKey, $sessionId, $rsaPrivateKey);
    }
}
