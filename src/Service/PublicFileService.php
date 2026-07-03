<?php

declare(strict_types=1);

namespace Mega\Service;

use Mega\Crypto\A32;
use Mega\Crypto\Attr;
use Mega\Crypto\Base64Url;
use Mega\Entity\FileInfo;
use Mega\Exception\ApiException;
use Mega\Exception\CryptoException;
use Mega\Exception\HttpException;
use Mega\Exception\InvalidLinkException;
use Mega\PublicLink;
use Mega\Transport\Connector;
use Mega\Transport\Downloader;

/**
 * Retrieves metadata and content for public MEGA file links, without
 * requiring an authenticated session.
 */
class PublicFileService
{
    /**
     * @var Connector
     */
    private $connector;

    /**
     * @var Downloader
     */
    private $downloader;

    public function __construct(Connector $connector, Downloader $downloader)
    {
        $this->connector = $connector;
        $this->downloader = $downloader;
    }

    /**
     * Retrieve metadata for a public file link.
     *
     * @throws InvalidLinkException
     * @throws ApiException
     * @throws HttpException
     * @throws CryptoException
     */
    public function getFileInfo(string $link): FileInfo
    {
        $parsed = $this->requirePublicFileLink($link);

        $response = $this->connector->send([
            'a'   => 'g',
            'p'   => $parsed->getHandle(),
            'g'   => 0,
            'ssl' => 1,
        ]);

        return $this->buildFileInfoFromPublicResponse($response, $parsed->getKey());
    }

    /**
     * Download a public file.
     * 
     * Returns decrypted file content as a string when
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
    public function download(string $link, $destination = null)
    {
        $parsed = $this->requirePublicFileLink($link);

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
}
