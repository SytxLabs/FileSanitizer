<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use Exception;
use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Scanner\ArchiveScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use ZipArchive;

final class ArchiveScannerTest extends TestCase
{
    private string $tempDir;

    /** @throws Exception */
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

        $report = (new ArchiveScanner(new FileChunker($outerZip)))->scan($outerZip, 'application/zip');

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

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_path_traversal'));
    }

    public function testSupportsOoxmlMimeTypesAndZipExtension(): void
    {
        $scanner = new ArchiveScanner();

        self::assertTrue($scanner->supports('application/zip', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/vnd.openxmlformats-officedocument.wordprocessingml.document', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/vnd.openxmlformats-officedocument.presentationml.presentation', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/octet-stream', '/tmp/x.ZIP'));
        self::assertFalse($scanner->supports('text/plain', '/tmp/x.txt'));
    }

    public function testCleanArchiveIsSafe(): void
    {
        $zipPath = $this->tempDir . '/clean.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('readme.txt', 'just some plain text');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($report->safe);
    }

    public function testDirectoryEntriesAreSkippedWithoutIssues(): void
    {
        $zipPath = $this->tempDir . '/withdir.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addEmptyDir('folder');
        $zip->addFromString('folder/readme.txt', 'text');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($report->safe);
    }

    public function testUnopenableArchiveIsFlagged(): void
    {
        $path = $this->tempDir . '/notazip.zip';
        file_put_contents($path, 'this is not a zip file');

        $report = (new ArchiveScanner(new FileChunker($path)))->scan($path, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_open_failed'));
    }

    public function testArchiveDepthExceededIsFlaggedForNestedArchive(): void
    {
        $nestedZip = $this->tempDir . '/nested.zip';
        $zip = new ZipArchive();
        $zip->open($nestedZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('a.txt', 'x');
        $zip->close();

        $outerZip = $this->tempDir . '/outer.zip';
        $zip = new ZipArchive();
        $zip->open($outerZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFile($nestedZip, 'nested.zip');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($outerZip), ['maxArchiveDepth' => 0]))->scan($outerZip, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_depth_exceeded'));
    }

    public function testEntryLimitExceededIsFlaggedAndScanIsTruncated(): void
    {
        $zipPath = $this->tempDir . '/manyentries.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('a.txt', 'a');
        $zip->addFromString('b.txt', 'b');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath), ['maxArchiveEntries' => 1]))->scan($zipPath, 'application/zip');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsIssueCode($report->issues, 'archive_entry_limit'));
    }

    public function testExpandedSizeLimitIsFlaggedAndStopsScanningFurtherEntries(): void
    {
        $zipPath = $this->tempDir . '/big.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('a.txt', str_repeat('a', 20));
        $zip->addFromString('b.html', '<script>evil()</script>');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath), ['maxExpandedBytes' => 5]))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'archive_size_limit'));
        self::assertFalse($this->containsIssueCode($report->issues, 'archive_embedded_script'));
    }

    public function testUnreadableEncryptedEntryIsFlagged(): void
    {
        $zipPath = $this->tempDir . '/encrypted.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('secret.txt', 'hidden content');
        $zip->setEncryptionIndex(0, ZipArchive::EM_AES_256, 'correct-password');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'archive_entry_read_failed'));
    }

    public function testEmbeddedVbaMacroIsFlagged(): void
    {
        $zipPath = $this->tempDir . '/macro.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('word/vbaProject.bin', 'binary macro data');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'office_macro'));
    }

    /** @return array<string, array{0: string}> */
    public static function activeXEntryNameProvider(): array
    {
        return [
            'activex control' => ['word/activeX/activeX1.bin'],
            'ole object' => ['word/embeddings/oleObject1.bin'],
        ];
    }

    /** @dataProvider activeXEntryNameProvider */
    public function testEmbeddedActiveXOrOleObjectIsFlagged(string $entryName): void
    {
        $zipPath = $this->tempDir . '/activex.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString($entryName, 'binary object data');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'office_activex'));
    }

    public function testExternalRelationshipTargetIsFlagged(): void
    {
        $zipPath = $this->tempDir . '/rels.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('word/_rels/document.xml.rels', '<Relationship TargetMode="External" Target="http://evil.test/x"/>');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'office_external_reference'));
    }

    /** @return array<string, array{0: string}> */
    public static function pathTraversalNameProvider(): array
    {
        return [
            'relative traversal' => ['../evil.txt'],
            'absolute leading slash' => ['/etc/passwd'],
            'windows drive letter' => ['c:/windows/system32/evil.dll'],
        ];
    }

    /** @dataProvider pathTraversalNameProvider */
    public function testPathTraversalVariantsAreFlagged(string $entryName): void
    {
        $zipPath = $this->tempDir . '/traversal2.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString($entryName, 'hello');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'archive_path_traversal'));
    }

    public function testNestedArchiveDetectedByMagicBytesEvenWithoutZipExtension(): void
    {
        $outerZip = $this->tempDir . '/magic.zip';
        $zip = new ZipArchive();
        $zip->open($outerZip, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('payload.bin', "PK\x03\x04" . str_repeat('x', 20));
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($outerZip)))->scan($outerZip, 'application/zip');

        self::assertTrue($this->containsIssueCode($report->issues, 'archive_open_failed'));
    }

    public function testTinyEntryContentIsNeverTreatedAsANestedZip(): void
    {
        $zipPath = $this->tempDir . '/tiny.zip';
        $zip = new ZipArchive();
        $zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
        $zip->addFromString('tiny.bin', 'PK');
        $zip->close();

        $report = (new ArchiveScanner(new FileChunker($zipPath)))->scan($zipPath, 'application/zip');

        self::assertTrue($report->safe);
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
