<?php

namespace SytxLabs\FileSanitizer\Tests\Scanner;

use PHPUnit\Framework\TestCase;
use RuntimeException;
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

    public function testThrowsWhenStreamNotInjected(): void
    {
        $this->expectException(RuntimeException::class);
        (new PdfScanner())->scan($this->path, 'application/pdf');
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

    public function testRecognizesPdfNameHexEscapeInRawScan(): void
    {
        // "/J#61vaScript" hex-decodes to "/JavaScript".
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj << /J#61vaScript 1 0 R >> endobj\n%%EOF");

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, 'pdf_javascript'));
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function rawPatternProvider(): array
    {
        return [
            'launch action' => ['/Launch (calc.exe)', 'pdf_launch_action'],
            'encrypted' => ['/Encrypt 3 0 R', 'pdf_encrypted'],
            'rich media' => ['/RichMedia 4 0 R', 'pdf_richmedia'],
            'xfa' => ['/XFA [1 0 R]', 'pdf_xfa'],
            'submit form' => ['/SubmitForm (http://evil.test)', 'pdf_submit_form'],
            'goto remote' => ['/GoToR (evil.pdf)', 'pdf_goto_remote'],
        ];
    }

    /** @dataProvider rawPatternProvider */
    public function testFlagsRawPattern(string $marker, string $expectedCode): void
    {
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj << " . $marker . " >> endobj\n%%EOF");

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, $expectedCode));
    }

    /** @return array<string, array{0: string, 1: string}> */
    public static function decodedMarkupPatternProvider(): array
    {
        return [
            'script tag' => ['<script>alert(1)</script>', 'xss_script_tag'],
            'javascript url' => ['href="javascript:alert(1)"', 'xss_javascript_url'],
            'inline handler' => ['<body onload="evil()">', 'xss_inline_handler'],
            'eval' => ['eval(atob("x"))', 'xss_eval'],
            'dom sink' => ['el.innerHTML = "x"', 'dom_sink'],
            'iframe embed' => ['<iframe src="evil.test">', 'iframe_embed'],
        ];
    }

    /** @dataProvider decodedMarkupPatternProvider */
    public function testFlagsDecodedMarkupPatternInsideFlateStream(string $payload, string $expectedCode): void
    {
        $compressed = gzcompress($payload);
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, $expectedCode));
    }

    public function testDecodesChainOfMultipleFilters(): void
    {
        $hidden = 'this.exportDataObject({}); /JavaScript trigger';
        $body = bin2hex(gzcompress($hidden)) . '>';
        $pdf = $this->buildPdf('/Filter [/ASCIIHexDecode /FlateDecode] ', $body);
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, 'pdf_javascript'));
    }

    public function testNestedDictionaryBracesInStreamDictAreParsedCorrectly(): void
    {
        $hidden = '/JavaScript inside nested dict stream';
        $compressed = gzcompress($hidden);
        $pdf = $this->buildPdf('/Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 5 >> ', $compressed);
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertTrue($this->containsCode($report->issues, 'pdf_javascript'));
    }

    public function testStreamWithNoPrecedingDictionaryIsSkippedWithoutCrashing(): void
    {
        // No "<< ... >>" appears anywhere before the "stream" keyword.
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj\nstream\nplain body\nendstream\nendobj\n%%EOF");

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testRejectsStreamExceedingDecodedOutputCap(): void
    {
        $compressed = gzcompress(str_repeat('A', 100));
        $pdf = $this->buildPdf('/Filter /FlateDecode ', $compressed);
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path), ['decodedOutputCap' => 10]))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    public function testRejectsStreamExceedingStreamBufferCapAsOverflow(): void
    {
        $compressed = gzcompress(str_repeat('A', 200));
        $pdf = $this->buildPdf('/Filter /FlateDecode ', $compressed);
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path), ['streamBufferCap' => 10]))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    public function testUnsupportedFilterNameIsRejectedAsUndecodable(): void
    {
        $pdf = $this->buildPdf('/Filter /Crypt ', 'irrelevant body');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertFalse($report->safe);
        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    public function testUndecodableObjectStreamDeclaredViaExplicitType(): void
    {
        $pdf = $this->buildPdf('/Type /ObjStm /Filter /Crypt ', 'irrelevant body');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_objstm_undecodable'));
    }

    public function testUndecodableObjectStreamDeclaredViaNAndFirstHeuristic(): void
    {
        $pdf = $this->buildPdf('/N 5 /First 20 /Filter /Crypt ', 'irrelevant body');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_objstm_undecodable'));
    }

    public function testUndecodableEmbeddedFileStream(): void
    {
        $pdf = $this->buildPdf('/Type /EmbeddedFile /Filter /Crypt ', 'irrelevant body');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_undecodable'));
    }

    public function testImageCodecFilterStreamIsSkippedEvenWithSuspiciousDecodedContent(): void
    {
        $pdf = $this->buildPdf('/Filter /DCTDecode ', '<script>evil</script>');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testGenericImageXObjectStreamIsSkippedEvenWithNonCodecFilter(): void
    {
        $pdf = $this->buildPdf('/Subtype /Image /Width 10 /Height 10 /Filter /FlateDecode ', gzcompress('<script>evil</script>'));
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testUnfilteredNonEmbeddedStreamIsSkipped(): void
    {
        $pdf = $this->buildPdf('', '<script>evil</script>');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testUnfilteredEmbeddedAttachmentWithExecutableSignatureIsRejected(): void
    {
        $pdf = $this->buildPdf('/Type /EmbeddedFile ', 'MZ' . str_repeat("\x90", 20));
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_executable'));
    }

    public function testUnfilteredEmbeddedAttachmentThatIsItselfAPdfIsRejected(): void
    {
        $pdf = $this->buildPdf('/Type /EmbeddedFile ', "%PDF-1.5\nnested content");
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_pdf'));
    }

    public function testEmptyEmbeddedAttachmentBodyIsIgnoredWithoutCrashing(): void
    {
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Type /EmbeddedFile /Length 0 >>\nstream\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testTwoDangerousEmbeddedAttachmentsOnlyProduceOneDedupedIssue(): void
    {
        $pdf = $this->buildPdf('/Type /EmbeddedFile ', 'MZ' . str_repeat("\x90", 20))
            . "\n1 0 obj\n<< /Type /EmbeddedFile /Length 6 >>\nstream\nPK\x03\x04XX\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        $matches = array_filter($report->issues, static fn ($issue) => $issue->code === 'pdf_embedded_executable');
        self::assertCount(1, $matches);
    }

    public function testEmbeddedExecutableAttachmentSpansManySmallChunksAndIsStillDetected(): void
    {
        $payload = 'MZ' . str_repeat('X', 500);
        $pdf = $this->buildPdf('/Type /EmbeddedFile ', $payload);
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path), ['bufferSize' => 32]))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_executable'));
    }

    public function testRawPatternSplitAcrossSmallChunkBoundaryIsStillDetected(): void
    {
        $pdf = "%PDF-1.4\n" . str_repeat('A', 55) . '/JavaScript ' . str_repeat('B', 5) . "\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path), ['bufferSize' => 64]))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_javascript'));
    }

    /**
     * scan()'s own read loop has a defensive break for a stream implementation that returns a
     * false/empty read before eof() itself reports true. A real file-backed stream cannot be made
     * to do this reliably (feof() timing depends on the OS buffering), so a stream double that
     * always reports eof()=false is used to force that specific path deterministically.
     */
    public function testScanLoopStopsWhenStreamReturnsFalseBeforeReportingEof(): void
    {
        file_put_contents($this->path, "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");

        $stream = new class ($this->path, new FileChunker($this->path)) implements \SytxLabs\FileSanitizer\Contracts\StreamInterface
        {
            private FileChunker $inner;

            public function __construct(string $path, ?FileChunker $inner = null)
            {
                $this->inner = $inner ?? new FileChunker($path);
            }

            public function filePath(): string
            {
                return $this->inner->filePath();
            }

            public function read(int $length): false|string
            {
                return $this->inner->read($length);
            }

            public function eof(): bool
            {
                return false;
            }

            public function tell(): false|int
            {
                return $this->inner->tell();
            }

            public function size(): false|int
            {
                return $this->inner->size();
            }

            public function seek(int $offset): void
            {
                $this->inner->seek($offset);
            }

            public function rewind(): void
            {
                $this->inner->rewind();
            }

            public function close(): void
            {
                $this->inner->close();
            }
        };

        $report = (new PdfScanner($stream))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testUnterminatedStreamAtEofIsStillInspected(): void
    {
        $payload = 'MZ' . str_repeat('X', 50);
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Type /EmbeddedFile /Length " . strlen($payload) . " >>\nstream\n" . $payload;
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_executable'));
    }

    public function testDecodedEmbeddedAttachmentIsInspectedAfterSuccessfulDecode(): void
    {
        $payload = 'MZ' . str_repeat('X', 50);
        $pdf = $this->buildPdf('/Type /EmbeddedFile /Filter /FlateDecode ', gzcompress($payload));
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($this->containsCode($report->issues, 'pdf_embedded_executable'));
    }

    public function testUnbalancedClosingBracesInPrecedingTextFallsBackToRawWindow(): void
    {
        $pdf = "%PDF-1.4\n>> orphan closer\nstream\nbody\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertTrue($report->safe);
    }

    public function testEmptyFilterArrayHasNoResolvableNameAndIsRejectedAsUnresolved(): void
    {
        $pdf = $this->buildPdf('/Filter [] ', 'body');
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    public function testBareFilterKeywordWithNoValueIsRejectedAsUnresolved(): void
    {
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Length 4 /Filter >>\nstream\nbody\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        self::assertSame('pdf_stream_undecodable', $report->issues[0]->code);
    }

    public function testSamePatternFoundInBothRawAndDecodedScanIsNotDuplicated(): void
    {
        $compressed = gzcompress('/JavaScript trigger');
        $pdf = "%PDF-1.4\n1 0 obj << /JavaScript 1 0 R >> endobj\n"
            . "2 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF";
        file_put_contents($this->path, $pdf);

        $report = (new PdfScanner(new FileChunker($this->path)))->scan($this->path, 'application/pdf');

        $matches = array_filter($report->issues, static fn ($issue) => $issue->code === 'pdf_javascript');
        self::assertCount(1, $matches);
    }

    private function buildPdf(string $dictExtra, string $body): string
    {
        return "%PDF-1.4\n1 0 obj\n<< " . $dictExtra . '/Length ' . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF";
    }
}
