<?php

namespace SytxLabs\FileSanitizer\Tests\Stream;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Stream\FileChunker;

final class FileChunkerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_chunker_');
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testChunksYieldFullContentInFixedSizePieces(): void
    {
        $content = str_repeat('a', 10) . str_repeat('b', 10) . str_repeat('c', 5);
        file_put_contents($this->path, $content);

        $chunker = new FileChunker($this->path, 10);
        $chunks = iterator_to_array($chunker->chunks());

        self::assertSame(['aaaaaaaaaa', 'bbbbbbbbbb', 'ccccc'], $chunks);
        $chunker->close();
    }

    public function testReadAllReturnsCompleteContent(): void
    {
        $content = random_bytes(4096);
        file_put_contents($this->path, $content);

        $chunker = new FileChunker($this->path, 512);

        self::assertSame($content, $chunker->readAll());
        $chunker->close();
    }

    public function testThrowsWhenFileDoesNotExist(): void
    {
        $this->expectException(RuntimeException::class);
        new FileChunker($this->path . '_missing');
    }
}
