<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Scanner\GenericPatternScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;

final class GenericPatternScannerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_generic_');
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testSupportsEveryFile(): void
    {
        $scanner = new GenericPatternScanner(new FileChunker($this->path));

        self::assertTrue($scanner->supports('application/octet-stream', '/tmp/x.bin'));
    }

    public function testFlagsScriptTag(): void
    {
        file_put_contents($this->path, '<script>alert(1)</script>');

        $report = (new GenericPatternScanner(new FileChunker($this->path)))->scan($this->path, 'text/plain');

        self::assertFalse($report->safe);
        self::assertSame('xss_script_tag', $report->issues[0]->code);
    }

    public function testCleanContentIsSafe(): void
    {
        file_put_contents($this->path, 'just plain text');

        $report = (new GenericPatternScanner(new FileChunker($this->path)))->scan($this->path, 'text/plain');

        self::assertTrue($report->safe);
    }

    public function testThrowsWhenStreamNotInjected(): void
    {
        $this->expectException(RuntimeException::class);
        (new GenericPatternScanner())->scan($this->path, 'text/plain');
    }
}
