<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Scanner\CompositeScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;

final class CompositeScannerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_composite_');
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testMergesIssuesFromEverySupportingScanner(): void
    {
        file_put_contents($this->path, '<script>alert(1)</script>');

        $scanner = new CompositeScanner(new FileChunker($this->path), [
            'scanners' => [
                $this->fakeScanner(true, ScanReport::unsafe([new Issue('fake_issue', 'fake', IssueSeverity::Error)])),
                $this->fakeScanner(false, ScanReport::clean()),
            ],
        ]);

        $report = $scanner->scan($this->path, 'text/plain');

        self::assertFalse($report->safe);
    }

    public function testCleanWhenNoScannerFlagsAnything(): void
    {
        file_put_contents($this->path, 'hello world');

        $report = (new CompositeScanner(new FileChunker($this->path)))->scan($this->path, 'text/plain');

        self::assertTrue($report->safe);
    }

    private function fakeScanner(bool $supports, ScanReport $report): ScannerInterface
    {
        return new class (new FileChunker($this->path), ['supports' => $supports, 'report' => $report]) implements ScannerInterface
        {
            private readonly bool $supports;

            private readonly ScanReport $report;

            public function __construct(?StreamInterface $stream = null, ?array $options = null)
            {
                $this->supports = $options['supports'];
                $this->report = $options['report'];
            }

            public function supports(string $mimeType, string $path): bool
            {
                return $this->supports;
            }

            public function scan(string $path, string $mimeType): ScanReport
            {
                return $this->report;
            }
        };
    }
}
