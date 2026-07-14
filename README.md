# mega-php

[![Latest Version](https://img.shields.io/packagist/v/enricodias/mega.svg)](https://packagist.org/packages/enricodias/mega)
[![PHP Version](https://img.shields.io/packagist/php-v/enricodias/mega.svg)](https://packagist.org/packages/enricodias/mega)
[![License](https://img.shields.io/packagist/l/enricodias/mega.svg)](LICENSE)

A PHP client for the [MEGA](https://mega.nz) cloud storage API.

`mega-php` handles the MEGA protocol details for you: authentication, AES/RSA key crypto, MAC verification, and chunked upload/download, exposed through a small service-oriented API built on PSR interfaces (PSR-7/17/18 HTTP, PSR-6 cache, PSR-3 logging).

## Requirements

- PHP 7.3 or 8.0+
- `ext-bcmath`, `ext-json`, `ext-openssl`
- A PSR-18 HTTP client, PSR-17 request/stream factories, and their implementations (e.g. [Guzzle](https://github.com/guzzle/guzzle)). If none are provided explicitly, they are auto-discovered at runtime via `php-http/discovery`.

## Installation

```bash
composer require enricodias/mega
```

If your project does not already depend on a PSR-18 HTTP client, install one so it can be auto-discovered:

```bash
composer require guzzlehttp/guzzle
```

## Quick start

The `Client` class is the main entry point for the package. It is not constructed directly; use `ClientFactory` (or `PsrClientFactory` in autowiring DI containers) to build one.

```php
use Mega\ClientFactory;

$client = (new ClientFactory())->create();

$fileInfo = $client->getPublicFileInfo('https://mega.nz/file/<handle>#<key>');

echo $fileInfo->getName();
echo $fileInfo->getSize();
```

## Building a client

### ClientFactory

`ClientFactory` offers a fluent API for cases where dependencies are constructed manually:

```php
use Mega\ClientFactory;
use Mega\Config;

$client = (new ClientFactory(new Config()))
    ->withHttpClient($httpClient)         // Psr\Http\Client\ClientInterface
    ->withRequestFactory($requestFactory) // Psr\Http\Message\RequestFactoryInterface
    ->withStreamFactory($streamFactory)   // Psr\Http\Message\StreamFactoryInterface
    ->withCachePool($cachePool)           // Psr\Cache\CacheItemPoolInterface
    ->create();
```

Any dependency that is not supplied is auto-discovered. Omitting all of them is enough for most applications:

```php
$client = (new ClientFactory())->create();
```

### PsrClientFactory

`PsrClientFactory` wraps `ClientFactory` behind a single constructor call so that DI containers capable of autowiring typed constructor parameters (but not fluent builder methods) can build a `Client` without any manual wiring code:

```php
use Mega\PsrClientFactory;

$client = (new PsrClientFactory(
    $config,
    $httpClient,
    $requestFactory,
    $streamFactory,
    $cachePool,
    $logger
))->getClient();
```

All constructor arguments are optional and nullable, so containers can supply only the services they have registered. Register `PsrClientFactory` in your container and type-hint `Client` where needed; the container calls `getClient()` to resolve it.

### Config

`Config` holds the API server URL and, optionally, login credentials used for automatic authentication:

```php
use Mega\Config;

$config = new Config(
    Config::SERVER_EUROPE, // or Config::SERVER_GLOBAL (default)
    'user@example.com',
    'password'
);
```

When email and password are set, any authenticated method call transparently logs in on first use, so an explicit `login()` call is not required.

### Logging

Any PSR-3 `LoggerInterface` implementation (e.g. [monolog/monolog](https://github.com/Seldaek/monolog)) can be passed to the factory to log requests, responses, and lifecycle events. Sensitive fields (passwords, keys, session tokens) are redacted before being logged.

## Authentication

```php
$session = $client->login('user@example.com', 'password');
```

Sessions can be exported and restored to avoid logging in on every request, for example when persisting the session between HTTP requests in a web application:

```php
$session = $client->exportSession();

// ...store $session (e.g. serialize it)...

$client->restoreSession($session);
```

Alternatively, pass a PSR-6 cache pool via `ClientFactory::withCachePool()` (or `PsrClientFactory`) to have sessions cached and restored automatically across `login()` calls with the same email.

## Working with public links

Public file and folder links do not require authentication:

```php
$fileInfo = $client->getPublicFileInfo($link);

$contents = $client->downloadPublicFile($link);

// Or stream directly into a file:
$stream = \fopen('/path/to/destination', 'wb');
$bytesWritten = $client->downloadPublicFile($link, $stream);
\fclose($stream);
```

## Working with an authenticated account

`listNodes()` returns every file and folder in the authenticated user's filesystem as `Mega\Entity\Node` objects:

```php
$nodes = $client->listNodes();

foreach ($nodes as $node) {
    echo $node->getName(), \PHP_EOL;
}
```

### Node types

A `Node` represents either a file or a folder. Its type is exposed through `getType()`, which returns one of the `Node::TYPE_FILE` or `Node::TYPE_FOLDER` constants:

```php
use Mega\Entity\Node;

foreach ($nodes as $node) {
    if ($node->getType() === Node::TYPE_FOLDER) {
        echo $node->getName(), ' is a folder', \PHP_EOL;
        continue;
    }

    echo $node->getName(), ' is a file', \PHP_EOL;
}
```

Only file nodes can be passed to `getFileInfo()`, `downloadFile()`, and used as the source of an upload's parent lookup; folder nodes are used as containers when listing, moving, or uploading.

### File metadata

`getFileInfo()` returns a `Mega\Entity\FileInfo` describing a file node. It exposes the file's name, size in bytes, and a temporary download URL:

```php
$fileInfo = $client->getFileInfo($node);

echo $fileInfo->getName();        // string
echo $fileInfo->getSize();        // int, bytes
echo $fileInfo->getDownloadUrl(); // string|null
```

### Downloading, uploading, and managing nodes

```php
$contents = $client->downloadFile($node);

$newNode = $client->uploadFile('/path/to/local/file.txt', $parentHandle);

$client->moveNode($node->getHandle(), $newParentHandle);

$client->deleteNode($node->getHandle());
```

`uploadFile()` also accepts a readable stream resource instead of a path:

```php
$stream = \fopen('php://temp', 'r+');
\fwrite($stream, $data);
\rewind($stream);

$node = $client->uploadFile($stream, $parentHandle, 'file.txt', \strlen($data));
```

When uploading from a stream, `$size` should be provided when known; it allows the client to skip measuring the stream itself.

## Error handling

All exceptions extend `Mega\Exception\MegaException`:

| Exception | Thrown when   |
|---|---|
| `AuthException` | No active session, or authentication fails |
| `ApiException` | The MEGA API returns an error code |
| `HttpException` | The underlying HTTP request fails |
| `InvalidLinkException`| A public link cannot be parsed |
| `CryptoException`| Decryption or MAC verification fails |

```php
use Mega\Exception\MegaException;

try {
    $client->downloadFile($node);
} catch (MegaException $e) {
    // handle any library error
}
```

## License

MIT. See [LICENSE](LICENSE).
