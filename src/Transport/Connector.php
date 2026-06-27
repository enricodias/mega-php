<?php

declare(strict_types=1);

namespace Mega\Transport;

use Mega\Exception\ApiException;
use Mega\Exception\HttpException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Sends JSON command arrays to the MEGA API and returns decoded responses.
 *
 * Each instance owns a monotonically increasing sequence number. Commands are
 * sent as a JSON array in the request body; the corresponding response array
 * element is returned directly to the caller.
 */
class Connector
{
    /**
     * @var string
     */
    private $apiUrl;

    /**
     * @var ClientInterface
     */
    private $httpClient;

    /**
     * @var RequestFactoryInterface
     */
    private $requestFactory;

    /**
     * @var StreamFactoryInterface
     */
    private $streamFactory;

    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * @var int
     */
    private $sequenceNumber;

    /**
     * @var string|null
     */
    private $sessionId;

    public function __construct(
        string $apiUrl,
        ClientInterface $httpClient,
        RequestFactoryInterface $requestFactory,
        StreamFactoryInterface $streamFactory,
        LoggerInterface $logger
    ) {
        $this->apiUrl = $apiUrl;
        $this->httpClient = $httpClient;
        $this->requestFactory = $requestFactory;
        $this->streamFactory = $streamFactory;
        $this->logger = $logger;
        $this->sequenceNumber = \random_int(0, \PHP_INT_MAX);
        $this->sessionId = null;
    }

    public function setSessionId(?string $sessionId): void
    {
        $this->sessionId = $sessionId;
    }

    /**
     * Send a single command and return the unwrapped response element.
     *
     * @param array<string, mixed> $command
     *
     * @return mixed
     *
     * @throws ApiException
     * @throws HttpException
     */
    public function send(array $command)
    {
        $url = $this->buildUrl();

        $body = \json_encode([$command]);

        $this->logger->debug('MEGA API request', ['url' => $url, 'body' => $body]);

        $stream = $this->streamFactory->createStream((string) $body);
        $request = $this->requestFactory
            ->createRequest('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($stream);

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            throw new HttpException('HTTP request failed: ' . $e->getMessage(), 0, $e);
        }

        $raw = (string) $response->getBody();

        $this->logger->debug('MEGA API response', ['body' => $raw]);

        $decoded = \json_decode($raw, true);

        if (!\is_array($decoded)) {
            $this->throwIfApiError($decoded);
            throw new HttpException(\sprintf('Unexpected MEGA API response: %s', $raw));
        }

        $result = $decoded[0];

        $this->throwIfApiError($result);

        return $result;
    }

    /**
     * @param mixed $value
     *
     * @throws ApiException
     */
    private function throwIfApiError($value): void
    {
        if (!\is_int($value) || $value >= 0) {
            return;
        }

        throw ApiException::fromCode($value);
    }

    private function buildUrl(): string
    {
        $url = \rtrim($this->apiUrl, '/') . '/cs?id=' . $this->sequenceNumber++;

        if ($this->sessionId !== null) {
            $url .= '&sid=' . \urlencode($this->sessionId);
        }

        return $url;
    }
}
