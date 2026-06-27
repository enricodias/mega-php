<?php

declare(strict_types=1);

namespace Mega\Tests;

use Mega\Exception\InvalidLinkException;
use Mega\PublicLink;
use PHPUnit\Framework\TestCase;

class PublicLinkTest extends TestCase
{
    /**
     * @return array<string, array<mixed>>
     */
    public function validLinkProvider(): array
    {
        return [
            'legacy file link' => [
                'https://mega.nz/#!AbCdEfGh!keyString-goes_here',
                PublicLink::TYPE_FILE,
                'AbCdEfGh',
                'keyString-goes_here',
            ],
            'legacy folder link' => [
                'https://mega.nz/#F!FolderHnd!folderKeyStr',
                PublicLink::TYPE_FOLDER,
                'FolderHnd',
                'folderKeyStr',
            ],
            'modern file link' => [
                'https://mega.nz/file/AbCdEfGh#keyString-goes_here',
                PublicLink::TYPE_FILE,
                'AbCdEfGh',
                'keyString-goes_here',
            ],
            'modern folder link' => [
                'https://mega.nz/folder/FolderHnd#folderKeyStr',
                PublicLink::TYPE_FOLDER,
                'FolderHnd',
                'folderKeyStr',
            ],
            'modern link with longer handle and key' => [
                'https://mega.nz/file/ABC12345#xyz-ABC_DEF123456',
                PublicLink::TYPE_FILE,
                'ABC12345',
                'xyz-ABC_DEF123456',
            ],
        ];
    }

    /**
     * @dataProvider validLinkProvider
     */
    public function testParseValidLink(
        string $link,
        string $expectedType,
        string $expectedHandle,
        string $expectedKey
    ): void {
        $parsed = PublicLink::parse($link);

        $this->assertSame($expectedType, $parsed->getType());
        $this->assertSame($expectedHandle, $parsed->getHandle());
        $this->assertSame($expectedKey, $parsed->getKey());
    }

    public function testIsFileReturnsTrueForFiletype(): void
    {
        $parsed = PublicLink::parse('https://mega.nz/file/AbCdEfGh#key');

        $this->assertTrue($parsed->isFile());
        $this->assertFalse($parsed->isFolder());
    }

    public function testIsFolderReturnsTrueForFoldertype(): void
    {
        $parsed = PublicLink::parse('https://mega.nz/folder/FolderHnd#key');

        $this->assertFalse($parsed->isFile());
        $this->assertTrue($parsed->isFolder());
    }

    /**
     * @return array<string, array<string>>
     */
    public function invalidLinkProvider(): array
    {
        return [
            'plain url no fragment'  => ['https://mega.nz/'],
            'unrelated url'          => ['https://example.com/something'],
            'legacy fragment no key' => ['https://mega.nz/#!HandleOnly'],
            'empty string'           => [''],
        ];
    }

    /**
     * @dataProvider invalidLinkProvider
     */
    public function testParseThrowsOnInvalidLink(string $link): void
    {
        $this->expectException(InvalidLinkException::class);

        PublicLink::parse($link);
    }
}
