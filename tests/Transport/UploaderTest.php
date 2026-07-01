<?php

declare(strict_types=1);

namespace Mega\Tests\Transport;

use GuzzleHttp\Client as GuzzleClient;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\HttpFactory;
use GuzzleHttp\Psr7\Response;
use Mega\Crypto\A32;
use Mega\Crypto\ChunkSizer;
use Mega\Crypto\NodeKey;
use Mega\Transport\Uploader;
use PHPUnit\Framework\TestCase;

class UploaderTest extends TestCase
{
    public function testUploadEncryptsChunkCorrectly(): void
    {
        $factory = new HttpFactory();

        $plaintext = \str_repeat('T', 16);
        $nodeKey = $this->fixedNodeKey();
        $aesKey = A32::toString(NodeKey::foldToAesKey($nodeKey));
        $iv = ChunkSizer::ivFromNodeKey($nodeKey);

        $expectedCipher = (string) \openssl_encrypt(
            $plaintext,
            'aes-128-ctr',
            $aesKey,
            \OPENSSL_RAW_DATA | \OPENSSL_ZERO_PADDING,
            $iv
        );

        $capturedPuts = [];
        $putMock = new MockHandler([new Response(200, [], 'completion-token')]);
        $putStack = HandlerStack::create($putMock);
        $putStack->push(function (callable $handler) use (&$capturedPuts) {
            return function ($request, array $options) use ($handler, &$capturedPuts) {
                $capturedPuts[] = $request;
                return $handler($request, $options);
            };
        });
        $putClient = new GuzzleClient(['handler' => $putStack]);

        $uploader = new Uploader($putClient, $factory, $factory);

        $stream = $this->makeStream($plaintext);
        $nodeKeyCopy = $nodeKey;
        $uploader->upload('https://upload.example.invalid', $stream, \strlen($plaintext), $nodeKeyCopy);

        $this->assertCount(1, $capturedPuts);

        $putBody = (string) $capturedPuts[0]->getBody();

        $this->assertSame($expectedCipher, $putBody);
    }

    public function testUploadWritesFileMacIntoNodeKey(): void
    {
        $factory = new HttpFactory();

        $plaintext = \str_repeat('T', 16);
        $nodeKey = $this->fixedNodeKey();

        $capturedPuts = [];
        $putMock = new MockHandler([new Response(200, [], 'completion-token')]);
        $putStack = HandlerStack::create($putMock);
        $putStack->push(function (callable $handler) use (&$capturedPuts) {
            return function ($request, array $options) use ($handler, &$capturedPuts) {
                $capturedPuts[] = $request;
                return $handler($request, $options);
            };
        });
        $putClient = new GuzzleClient(['handler' => $putStack]);

        $uploader = new Uploader($putClient, $factory, $factory);

        $stream = $this->makeStream($plaintext);
        $nodeKeyCopy = $nodeKey;
        $uploader->upload('https://upload.example.invalid', $stream, \strlen($plaintext), $nodeKeyCopy);

        // computed manually
        $expected = [
            16909060,
            84281096,
            1574991273,
            3521221330,
            286397204,
            353769240,
            1424653989,
            3706691010,
        ];

        $this->assertSame($expected, $nodeKeyCopy);
    }

    /**
     * Fixed 8-element a32 node key used in Uploader unit tests.
     *
     * @return array<int>
     */
    private function fixedNodeKey(): array
    {
        return [0x01020304, 0x05060708, 0x090a0b0c, 0x0d0e0f10,
                0x11121314, 0x15161718, 0x191a1b1c, 0x1d1e1f20];
    }

    /**
     * @return resource
     */
    private function makeStream(string $content)
    {
        $stream = \fopen('php://memory', 'rb+');
        \fwrite($stream, $content);
        \rewind($stream);
        return $stream;
    }
}
