<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Scanner\SvgScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;

final class SvgScannerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_svg_') . '.svg';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testFlagsForeignObject(): void
    {
        file_put_contents($this->path, '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>');

        $report = (new SvgScanner(new FileChunker($this->path)))->scan($this->path, 'image/svg+xml');

        self::assertFalse($report->safe);
    }

    public function testCleanSvgIsSafe(): void
    {
        file_put_contents($this->path, '<svg><circle cx="5" cy="5" r="4" /></svg>');

        $report = (new SvgScanner(new FileChunker($this->path)))->scan($this->path, 'image/svg+xml');

        self::assertTrue($report->safe);
    }

    public function testSupportsSvgMimeTypeAndExtension(): void
    {
        file_put_contents($this->path, '<svg></svg>');
        $scanner = new SvgScanner(new FileChunker($this->path));

        self::assertTrue($scanner->supports('image/svg+xml', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/octet-stream', '/tmp/x.svg'));
        self::assertFalse($scanner->supports('text/plain', '/tmp/x.txt'));
    }

    public function testThrowsWhenStreamNotInjected(): void
    {
        $this->expectException(RuntimeException::class);
        (new SvgScanner())->scan($this->path, 'image/svg+xml');
    }
}
