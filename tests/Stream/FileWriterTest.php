<?php

namespace SytxLabs\FileSanitizer\Tests\Stream;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class FileWriterTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_writer_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->removeRecursively($this->tempDir);
    }

    private function removeRecursively(string $path): void
    {
        if (is_file($path)) {
            @unlink($path);
            return;
        }
        if (!is_dir($path)) {
            return;
        }
        foreach (glob($path . '/*') ?: [] as $entry) {
            $this->removeRecursively($entry);
        }
        @rmdir($path);
    }

    public function testWritesDataAndTracksBytesWritten(): void
    {
        $path = $this->tempDir . '/out.bin';
        $writer = new FileWriter($path);

        $writer->write('hello ');
        $writer->write('world');
        self::assertSame(11, $writer->size());
        $writer->close();

        self::assertSame('hello world', file_get_contents($path));
    }

    public function testCreatesMissingOutputDirectory(): void
    {
        $path = $this->tempDir . '/nested/deep/out.bin';
        $writer = new FileWriter($path);
        $writer->write('data');
        $writer->close();

        self::assertTrue(is_dir($this->tempDir . '/nested/deep'));
        self::assertSame('data', file_get_contents($path));
    }

    public function testDestructClosesHandleAutomatically(): void
    {
        $path = $this->tempDir . '/auto-close.bin';
        (function () use ($path): void {
            $writer = new FileWriter($path);
            $writer->write('gone-out-of-scope');
        })();

        self::assertSame('gone-out-of-scope', file_get_contents($path));
    }

    /**
     * mkdir() raises a PHP warning (not just a false return) when the target already exists as a
     * regular file. That warning is suppressed here the same way it would be outside PHPUnit's
     * strict warning-to-exception handler, so the constructor's own failure guard is what's under
     * test rather than PHPUnit's warning conversion.
     */
    public function testThrowsWhenOutputDirectoryCannotBeCreated(): void
    {
        $blocker = $this->tempDir . '/blocker';
        file_put_contents($blocker, 'i am a file, not a directory');

        $this->expectException(RuntimeException::class);
        @new FileWriter($blocker . '/out.bin');
    }

    /** @see testThrowsWhenOutputDirectoryCannotBeCreated for why the @ suppression is needed. */
    public function testThrowsWhenFileCannotBeOpenedForWriting(): void
    {
        $this->expectException(RuntimeException::class);
        @new FileWriter($this->tempDir);
    }
}
