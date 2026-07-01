<?php

declare(strict_types=1);

namespace Mega;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\NodeKey;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\Session;
use Mega\Entity\TransferResult;
use Mega\Exception\ApiException;
use Mega\Exception\AuthException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Exception\InvalidLinkException;
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
     * @var Downloader
     */
    private $downloader;

    /**
     * @var Uploader
     */
    private $uploader;

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

    public function __construct(
        Connector $connector,
        Downloader $downloader,
        Uploader $uploader,
        ?LoggerInterface $logger = null,
        ?SessionCache $sessionCache = null,
        ?SessionAuthenticator $sessionAuthenticator = null
    ) {
        $this->connector = $connector;
        $this->downloader = $downloader;
        $this->uploader = $uploader;
        $this->logger = $logger !== null ? $logger : new NullLogger();
        $this->sessionCache = $sessionCache;
        $this->session = null;
        $this->sessionAuthenticator = $sessionAuthenticator !== null ? $sessionAuthenticator : new SessionAuthenticator();
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
        $parsed = $this->requirePublicFileLink($link);

        $this->logger->info('Requesting public file info', ['handle' => $parsed->getHandle()]);

        $response = $this->connector->send([
            'a'   => 'g',
            'p'   => $parsed->getHandle(),
            'g'   => 0,
            'ssl' => 1,
        ]);

        return $this->buildFileInfoFromPublicResponse($response, $parsed->getKey());
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
        $parsed = $this->requirePublicFileLink($link);

        $this->logger->info('Downloading public file', ['handle' => $parsed->getHandle()]);

        $response = $this->connector->send([
            'a'   => 'g',
            'p'   => $parsed->getHandle(),
            'g'   => 1,
            'ssl' => 1,
        ]);

        $downloadUrl = $response['g'] ?? null;
        $size = $response['s'] ?? null;

        if (!\is_string($downloadUrl) || !\is_int($size)) {
            throw new CryptoException('Public file info response is missing download URL or size.');
        }

        $nodeKey = A32::fromBase64($parsed->getKey());

        if ($destination !== null) {
            return $this->downloader->download($downloadUrl, $size, $nodeKey, $destination);
        }

        return $this->downloader->downloadToString($downloadUrl, $size, $nodeKey);
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

        $response = $this->connector->send([
            'a' => 'f',
            'c' => 1,
        ]);

        $rawNodes = $response['f'] ?? [];

        if (!\is_array($rawNodes)) {
            return [];
        }

        $masterKeyStr = A32::toString($this->session->getMasterKey());

        $nodes = [];
        foreach ($rawNodes as $raw) {
            $type = isset($raw['t']) ? (int) $raw['t'] : -1;

            if ($type !== Node::TYPE_FILE && $type !== Node::TYPE_FOLDER) {
                continue;
            }

            $handle = (string) ($raw['h'] ?? '');
            $rawKey = (string) ($raw['k'] ?? '');

            if ($handle === '' || $rawKey === '') {
                continue;
            }

            $node = $this->buildNodeFromRaw($handle, $type, $rawKey, $raw, $masterKeyStr);

            if ($node === null) {
                continue;
            }

            $nodes[] = $node;
        }

        return $nodes;
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
        $nodeKey = NodeKey::decryptNodeKey($node->getEncryptedKey(), $masterKeyStr);

        $response = $this->connector->send([
            'a'   => 'g',
            'n'   => $node->getHandle(),
            'g'   => 0,
            'ssl' => 1,
        ]);

        return $this->buildFileInfoFromNodeResponse($response, $nodeKey);
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
        $nodeKey = NodeKey::decryptNodeKey($node->getEncryptedKey(), $masterKeyStr);

        $response = $this->connector->send([
            'a'   => 'g',
            'n'   => $node->getHandle(),
            'g'   => 1,
            'ssl' => 1,
        ]);

        $downloadUrl = $response['g'] ?? null;
        $size = $response['s'] ?? null;

        if (!\is_string($downloadUrl) || !\is_int($size)) {
            throw new CryptoException('File info response is missing download URL or size.');
        }

        if ($destination !== null) {
            return $this->downloader->download($downloadUrl, $size, $nodeKey, $destination);
        }

        return $this->downloader->downloadToString($downloadUrl, $size, $nodeKey);
    }

    /**
     * Upload a file to the given parent node.
     *
     * $source may be a readable stream resource or a local file path string.
     * If $name is null and $source is a path, the basename of the path is used.
     * If $name is null and $source is a stream, the name defaults to 'upload'.
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
    public function uploadFile($source, string $parentHandle = '', ?string $name = null): TransferResult
    {
        $this->requireSession();

        list($stream, $size, $resolvedName) = $this->resolveSource($source, $name);

        if ($size === 0) {
            throw new \InvalidArgumentException('Cannot upload an empty file.');
        }

        $this->logger->info('Uploading file', ['name' => $resolvedName, 'size' => $size, 'parent' => $parentHandle]);

        $uploadResponse = $this->connector->send([
            'a' => 'u',
            's' => $size,
        ]);

        $uploadUrl = $uploadResponse['p'] ?? null;

        if (!\is_string($uploadUrl) || $uploadUrl === '') {
            throw new ApiException('Upload command did not return a valid upload URL.', 0);
        }

        $nodeKey = NodeKey::generateNodeKey();

        $completionToken = $this->uploader->upload($uploadUrl, $stream, $size, $nodeKey);

        $masterKeyStr = A32::toString($this->session->getMasterKey());
        $encryptedNodeKey = Aes::encryptKey($masterKeyStr, $nodeKey);
        $encryptedNodeKeyB64 = A32::toBase64($encryptedNodeKey);

        $attrCiphertext = Attr::encrypt(['n' => $resolvedName], $nodeKey);
        $attrB64 = Base64Url::encode($attrCiphertext);

        $nodeCreateResponse = $this->connector->send([
            'a' => 'p',
            't' => $parentHandle,
            'n' => [
                [
                    'h' => $completionToken,
                    't' => Node::TYPE_FILE,
                    'a' => $attrB64,
                    'k' => $encryptedNodeKeyB64,
                ],
            ],
        ]);

        $createdNodes = $nodeCreateResponse['f'] ?? [];

        if (!\is_array($createdNodes) || \count($createdNodes) === 0) {
            throw new ApiException('Node-create command returned no nodes.', 0);
        }

        $raw = $createdNodes[0];
        $handle = (string) ($raw['h'] ?? '');

        $node = new Node(
            $handle,
            Node::TYPE_FILE,
            $resolvedName,
            $encryptedNodeKeyB64
        );

        return new TransferResult($node);
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
        if ($handle === '') {
            throw new \InvalidArgumentException('$handle must not be empty.');
        }

        $this->requireSession();

        $this->logger->info('Deleting node', ['handle' => $handle]);

        $this->connector->send([
            'a' => 'd',
            'n' => $handle,
        ]);
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
        if ($handle === '') {
            throw new \InvalidArgumentException('$handle must not be empty.');
        }

        if ($parentHandle === '') {
            throw new \InvalidArgumentException('$parentHandle must not be empty.');
        }

        $this->requireSession();

        $this->logger->info('Moving node', ['handle' => $handle, 'parent' => $parentHandle]);

        $this->connector->send([
            'a' => 'm',
            'n' => $handle,
            't' => $parentHandle,
        ]);
    }

    /**
     * @param array<string, mixed> $response
     *
     * @throws ApiException
     * @throws CryptoException
     */
    private function buildFileInfoFromPublicResponse(array $response, string $linkKey): FileInfo
    {
        $nodeKey = A32::fromBase64($linkKey);

        if (!\array_key_exists('s', $response) || !\is_int($response['s'])) {
            throw new ApiException('Public file info response is missing a valid size.', 0);
        }

        $name = '';
        if (\array_key_exists('at', $response)) {
            $attrCiphertext = Base64Url::decode((string) $response['at']);
            $attrs = Attr::decrypt($attrCiphertext, $nodeKey);
            $name = (string) ($attrs['n'] ?? '');
        }

        $downloadUrl = \array_key_exists('g', $response) ? (string) $response['g'] : null;

        return new FileInfo($name, $response['s'], $downloadUrl !== '' ? $downloadUrl : null);
    }

    /**
     * Build a FileInfo from an authenticated 'g' command response.
     *
     * @param array<string, mixed> $response
     * @param array<int>           $nodeKey  Decrypted a32 node key
     *
     * @throws CryptoException
     */
    private function buildFileInfoFromNodeResponse(array $response, array $nodeKey): FileInfo
    {
        $name = '';
        if (\array_key_exists('at', $response)) {
            $attrCiphertext = Base64Url::decode((string) $response['at']);
            $attrs = Attr::decrypt($attrCiphertext, $nodeKey);
            $name = (string) ($attrs['n'] ?? '');
        }

        $size = \array_key_exists('s', $response) ? (int) $response['s'] : 0;
        $downloadUrl = \array_key_exists('g', $response) ? (string) $response['g'] : null;

        return new FileInfo($name, $size, $downloadUrl !== '' ? $downloadUrl : null);
    }

    /**
     * Try to build a Node from a raw 'f' API response element.
     *
     * Returns null when the node key or attributes cannot be decrypted.
     *
     * @param array<string, mixed> $raw          Single element from the 'f' array
     * @param string               $masterKeyStr 16-byte master key string
     */
    private function buildNodeFromRaw(string $handle, int $type, string $rawKey, array $raw, string $masterKeyStr): ?Node
    {
        try {
            $nodeKey = NodeKey::decryptNodeKey($rawKey, $masterKeyStr);
        } catch (\Throwable $e) {
            $this->logger->debug('Skipping node: could not decrypt key', ['handle' => $handle]);
            return null;
        }

        $name = '';
        if (\array_key_exists('a', $raw) && $raw['a'] !== '') {
            try {
                $attrCiphertext = Base64Url::decode((string) $raw['a']);
                $attrs = Attr::decrypt($attrCiphertext, $nodeKey);
                $name = (string) ($attrs['n'] ?? '');
            } catch (\Throwable $e) {
                $this->logger->debug('Could not decrypt node attributes', ['handle' => $handle]);
            }
        }

        return new Node($handle, $type, $name, $rawKey);
    }

    /**
     * Resolve $source to a stream resource, total size, and filename.
     *
     * @param string|resource $source
     * @param string|null     $name
     *
     * @return array{0: resource, 1: int, 2: string}
     *
     * @throws \InvalidArgumentException
     */
    private function resolveSource($source, ?string $name): array
    {
        if (\is_string($source)) {
            if (!\file_exists($source)) {
                throw new \InvalidArgumentException(\sprintf('Source file does not exist: %s', $source));
            }

            $stream = \fopen($source, 'rb');

            if ($stream === false) {
                throw new \InvalidArgumentException(\sprintf('Cannot open source file for reading: %s', $source));
            }

            $size = (int) \filesize($source);
            $resolvedName = $name ?? \basename($source);

            return [$stream, $size, $resolvedName];
        }

        if (!\is_resource($source)) {
            throw new \InvalidArgumentException('$source must be a file path string or a readable stream resource.');
        }

        $stat = \fstat($source);
        $size = ($stat !== false && \array_key_exists('size', $stat)) ? (int) $stat['size'] : 0;
        $resolvedName = $name ?? 'upload';

        return [$source, $size, $resolvedName];
    }

    /**
     * Parse a public link, requiring it to be a file link with a valid
     * 8-word file node key.
     *
     * @throws InvalidLinkException
     */
    private function requirePublicFileLink(string $link): PublicLink
    {
        $parsed = PublicLink::parse($link);

        if (!$parsed->isFile()) {
            throw new InvalidLinkException(\sprintf('Expected a MEGA file link, got a folder link: %s', $link));
        }

        if (\count(A32::fromBase64($parsed->getKey())) !== 8) {
            throw new InvalidLinkException(\sprintf('MEGA file link key must decode to 8 words: %s', $link));
        }

        return $parsed;
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
