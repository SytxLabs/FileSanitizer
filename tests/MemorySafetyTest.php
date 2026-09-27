<?php

namespace SytxLabs\FileSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\PdfSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\TextLikeSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;
use SytxLabs\FileSanitizer\Scanner\CompositeScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

/**
 * Proves the actual scenario this session's work was about: a file larger than the process'
 * memory_limit must not crash the process. memory_limit is lowered for the duration of each test
 * and every component under test is streamed, so it should never need to hold the whole (larger)
 * file in memory at once.
 */
final class MemorySafetyTest extends TestCase
{
    private string $tempDir;

    private false|string $originalMemoryLimit;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_memtest_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
        $this->originalMemoryLimit = ini_get('memory_limit');
    }

    protected function tearDown(): void
    {
        ini_set('memory_limit', $this->originalMemoryLimit === false ? '-1' : $this->originalMemoryLimit);
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testScansAndSanitizesTextFileLargerThanMemoryLimit(): void
    {
        $input = $this->writeFileOfSize($this->tempDir . '/large.txt', 24 * 1024 * 1024, 'plain text payload. ');
        $output = $this->tempDir . '/large.out.txt';

        $this->limitMemoryToCurrentUsagePlus(12 * 1024 * 1024);

        $scan = (new CompositeScanner(new FileChunker($input)))->scan($input, 'text/plain');
        self::assertTrue($scan->safe);

        (new TextLikeSanitizer())->sanitize($input, $output);
        self::assertFileExists($output);
        self::assertSame(filesize($input), filesize($output));
    }

    public function testSanitizesWavFileLargerThanMemoryLimit(): void
    {
        $input = $this->tempDir . '/large.wav';
        $handle = fopen($input, 'wb');
        $dataPayload = 24 * 1024 * 1024;
        fwrite($handle, 'RIFF' . pack('V', 4 + 8 + $dataPayload) . 'WAVE');
        fwrite($handle, 'data' . pack('V', $dataPayload));
        $this->writeRepeatedBytes($handle, $dataPayload, "\x01\x02\x03\x04");
        fclose($handle);
        $output = $this->tempDir . '/large.out.wav';

        $this->limitMemoryToCurrentUsagePlus(12 * 1024 * 1024);

        $report = (new AudioSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
        self::assertFileExists($output);
        self::assertNotEmpty($report->issues);
    }

    public function testSanitizesMkvFileLargerThanMemoryLimit(): void
    {
        $input = $this->writeFileOfSize($this->tempDir . '/large.mkv', 24 * 1024 * 1024, 'video frame filler. ');
        $output = $this->tempDir . '/large.out.mkv';

        $this->limitMemoryToCurrentUsagePlus(12 * 1024 * 1024);

        $report = (new VideoSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
        self::assertFileExists($output);
        self::assertNotEmpty($report->issues);
    }

    public function testSanitizesPdfWithOversizedUnfilteredStreamLargerThanMemoryLimit(): void
    {
        $input = $this->tempDir . '/large.pdf';
        $handle = fopen($input, 'wb');
        fwrite($handle, "%PDF-1.4\n1 0 obj\n<< /Length " . (24 * 1024 * 1024) . " >>\nstream\n");
        $this->writeRepeatedBytes($handle, 24 * 1024 * 1024, 'pdf content filler bytes. ');
        fwrite($handle, "\nendstream\nendobj\n%%EOF");
        fclose($handle);
        $output = $this->tempDir . '/large.out.pdf';

        $this->limitMemoryToCurrentUsagePlus(12 * 1024 * 1024);

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
        self::assertFileExists($output);
        self::assertNotEmpty($report->issues);
    }

    private function limitMemoryToCurrentUsagePlus(int $headroom): void
    {
        ini_set('memory_limit', (string) (memory_get_usage(true) + $headroom));
    }

    private function writeFileOfSize(string $path, int $size, string $pattern): string
    {
        $handle = fopen($path, 'wb');
        $this->writeRepeatedBytes($handle, $size, $pattern);
        fclose($handle);
        return $path;
    }

    /** @param resource $handle */
    private function writeRepeatedBytes(mixed $handle, int $size, string $pattern): void
    {
        $block = str_repeat($pattern, round((65536 / strlen($pattern)) + 1));
        $written = 0;
        while ($written < $size) {
            $piece = substr($block, 0, min(strlen($block), $size - $written));
            fwrite($handle, $piece);
            $written += strlen($piece);
        }
    }
}
