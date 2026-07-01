<?php

declare(strict_types=1);

namespace Mega\Service;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Crypto\NodeKey;
use Mega\Entity\FileInfo;
use Mega\Entity\Node;
use Mega\Entity\TransferResult;
use Mega\Exception\ApiException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;
use Mega\Transport\Uploader;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Lists, inspects, and downloads nodes in an authenticated user's MEGA
 * filesystem. Stateless: the caller's master key is passed in as a
 * parameter rather than held internally.
 */
class NodeService
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

    public function __construct(
        Connector $connector,
        Downloader $downloader,
        Uploader $uploader,
        ?LoggerInterface $logger = null
    ) {
        $this->connector = $connector;
        $this->downloader = $downloader;
        $this->uploader = $uploader;
        $this->logger = $logger !== null ? $logger : new NullLogger();
    }

    /**
     * List all nodes in the authenticated user's filesystem.
     *
     * Returns file and folder nodes with decrypted names. Nodes whose keys
     * cannot be decrypted are silently skipped.
     *
     * @return Node[]
     *
     * @throws ApiException
     * @throws HttpException
     */
    public function listNodes(string $masterKeyStr): array
    {
        $response = $this->connector->send([
            'a' => 'f',
            'c' => 1,
        ]);

        $rawNodes = $response['f'] ?? [];

        if (!\is_array($rawNodes)) {
            return [];
        }

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
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function getFileInfo(Node $node, string $masterKeyStr): FileInfo
    {
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
     * @param string        $masterKeyStr
     * @param resource|null $destination
     *
     * @return string|int
     *
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function download(Node $node, string $masterKeyStr, $destination = null)
    {
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
     * @param string          $masterKeyStr
     * @param string|null     $name
     *
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     * @throws \InvalidArgumentException
     */
    public function upload($source, string $parentHandle, string $masterKeyStr, ?string $name = null): TransferResult
    {
        list($stream, $size, $resolvedName) = $this->resolveSource($source, $name);

        if ($size === 0) {
            throw new \InvalidArgumentException('Cannot upload an empty file.');
        }

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
}
