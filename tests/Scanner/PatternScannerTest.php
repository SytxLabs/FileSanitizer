<?php

declare(strict_types=1);

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Scanner\PatternScanner;
use ZipArchive;

final class PatternScannerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_test_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        $this->deleteTree($this->tempDir);
    }

    public function testFlagsNestedZipWithScriptPayload(): void
    {
        $nestedZip = $this->tempDir . '/nested.zip';
        $zip = new ZipArchive();
        $zip->open($nestedZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('payload.html', '<div onclick="alert(1)">x</div>');
        $zip->close();

        $outerZip = $this->tempDir . '/outer.zip';
        $zip = new ZipArchive();
        $zip->open($outerZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFile($nestedZip, 'nested.zip');
        $zip->close();

        $report = (new PatternScanner())->scan($outerZip, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_embedded_script'));
    }

    public function testFlagsArchivePathTraversalEntry(): void
    {
        $zipPath = $this->tempDir . '/traversal.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('../evil.txt', 'hello');
        $zip->close();

        $report = (new PatternScanner())->scan($zipPath, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_path_traversal'));
    }

    /** @param array<int, object> $issues */
    private function containsIssueCode(array $issues, string $code): bool
    {
        foreach ($issues as $issue) {
            if (isset($issue->code) && $issue->code === $code) {
                return true;
            }
        }

        return false;
    }

    private function deleteTree(string $path): void
    {
        if (!is_dir($path)) {
            @unlink($path);
            return;
        }

        $items = scandir($path) ?: [];
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $this->deleteTree($path . '/' . $item);
        }

        @rmdir($path);
    }
}
