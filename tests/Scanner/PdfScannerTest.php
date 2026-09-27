<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Scanner\PdfScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;

final class PdfScannerTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_pdf_') . '.pdf';
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testSupportsPdfMimeTypeAndExtension(): void
    {
        file_put_contents($this->path, '%PDF-1.4');
        $scanner = new PdfScanner(new FileChunker($this->path));

        self::assertTrue($scanner->supports('application/pdf', '/tmp/x.dat'));
        self::assertTrue($scanner->supports('application/octet-stream', '/tmp/x.pdf'));
        self::assertFalse($scanner->supports('text/plain', '/tmp/x.txt'));
    }

    public function testFlagsAdditionalActionsMarker(): void
    {
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj << /AA << /O 5 0 R >> >> endobj\n%%EOF");

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertSame('pdf_additional_actions', $report->issues[0]->code);
    }

    public function testFlagsJavaScriptHiddenInsideFlateDecodeStream(): void
    {
        $hiddenJs = 'this.exportDataObject({cName:"x"}); /JavaScript trigger';
        $compressed = gzcompress($hiddenJs);

        $pdf = "%PDF-1.4\n"
            . "1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, 'pdf_javascript'));
    }

    public function testRejectsStreamWithUndecodableFilter(): void
    {
        $body = 'not really compressed data';
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    /** @param array<int, object> $issues */
    private function containsCode(array $issues, string $code): bool
    {
        foreach ($issues as $issue) {
            if ($issue->code === $code) {
                return true;
            }
        }
        return false;
    }

    public function testCleanPdfIsSafe(): void
    {
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }
}
