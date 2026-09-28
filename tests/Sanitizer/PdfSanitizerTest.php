<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Sanitizer\PdfSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

class PdfSanitizerTest extends TestCase
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
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testRemovesScriptHandlersDangerousUrlsAndMetaRefresh(): void
    {
        $input = $this->tempDir . '/input.pdf';
        $output = $this->tempDir . '/output.pdf';
        file_put_contents($input, '%PDF-1.7
        1 0 obj
        <</Pages 1 0 R /OpenAction 2 0 R>>
        2 0 obj
        <</S /JavaScript /JS (app.alert(1))>>
        trailer
        <</Root 1 0 R>>');

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
        $clean = (string) file_get_contents($output);
        self::assertStringContainsString('PDF-1.7', $clean);
        self::assertStringContainsString('1 0 obj', $clean);
        self::assertStringContainsString('2 0 obj', $clean);
        self::assertStringNotContainsString('app.alert', strtolower($clean));
    }

    public function testNeutralizesJavaScriptHiddenInsideFlateDecodeStream(): void
    {
        $input = $this->tempDir . '/hidden.pdf';
        $output = $this->tempDir . '/hidden.sanitized.pdf';

        $hiddenJs = 'this.exportDataObject({cName:"x"}); /JavaScript trigger';
        $compressed = gzcompress($hiddenJs);

        file_put_contents($input, "%PDF-1.4\n"
            . '1 0 obj' . "\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
        $clean = (string) file_get_contents($output);

        self::assertStringNotContainsString($compressed, $clean);
    }

    public function testSupportsPdfMimeTypeAndExtension(): void
    {
        $sanitizer = new PdfSanitizer();

        self::assertTrue($sanitizer->supports('application/pdf', '/tmp/x.dat'));
        self::assertTrue($sanitizer->supports('application/octet-stream', '/tmp/x.PDF'));
        self::assertFalse($sanitizer->supports('text/plain', '/tmp/x.txt'));
    }

    public function testThrowsWhenActiveContentIsHiddenInStreamAndSanitizeAlwaysIsFalse(): void
    {
        $input = $this->tempDir . '/hidden.pdf';
        $output = $this->tempDir . '/hidden.sanitized.pdf';

        $compressed = gzcompress('/JavaScript trigger');
        file_put_contents($input, "%PDF-1.4\n"
            . '1 0 obj' . "\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF");

        $this->expectException(\RuntimeException::class);
        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, false);
    }

    public function testThrowsWhenStreamOrOutputNotInjected(): void
    {
        $input = $this->tempDir . '/input.pdf';
        $output = $this->tempDir . '/output.pdf';
        file_put_contents($input, '%PDF-1.4');

        $this->expectException(RuntimeException::class);
        (new PdfSanitizer())->sanitize($input, $output);
    }

    public function testThrowsWhenStreamSizeCannotBeDetermined(): void
    {
        $input = $this->tempDir . '/input.pdf';
        $output = $this->tempDir . '/output.pdf';
        file_put_contents($input, '%PDF-1.4');

        $stream = new class implements StreamInterface
        {
            public function __construct(string $path = '')
            {
            }

            public function filePath(): string
            {
                return '';
            }

            public function read(int $length): false|string
            {
                return false;
            }

            public function eof(): bool
            {
                return true;
            }

            public function tell(): false|int
            {
                return 0;
            }

            public function size(): false|int
            {
                return false;
            }

            public function seek(int $offset): void
            {
            }

            public function rewind(): void
            {
            }

            public function close(): void
            {
            }
        };

        $this->expectException(RuntimeException::class);
        (new PdfSanitizer($stream, new FileWriter($output)))->sanitize($input, $output);
    }

    public function testCleanPdfWithNoActiveContentOrMetadataDoesNotThrowAndReportsUnchanged(): void
    {
        $input = $this->tempDir . '/clean.pdf';
        $output = $this->tempDir . '/clean.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $this->assertFalse($report->metadataRemoved);
        $codes = array_map(static fn ($issue) => $issue->code, $report->issues);
        $this->assertContains('pdf_best_effort_cleanup', $codes);
        $this->assertNotContains('pdf_active_content_removed', $codes);
    }

    public function testRemovesDocumentInfoMetadataFields(): void
    {
        $input = $this->tempDir . '/meta.pdf';
        $output = $this->tempDir . '/meta.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /Title (Secret Report) /Author (Jane Doe) >> endobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString('Secret Report', $clean);
        self::assertStringNotContainsString('Jane Doe', $clean);
        self::assertTrue($report->metadataRemoved);
    }

    public function testRemovesXmpMetadataPacket(): void
    {
        $input = $this->tempDir . '/xmp.pdf';
        $output = $this->tempDir . '/xmp.out.pdf';
        $xmp = '<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta>secret-author-name</x:xmpmeta><?xpacket end="w"?>';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /Metadata 2 0 R >> endobj\n2 0 obj " . $xmp . " endobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString('secret-author-name', $clean);
    }

    public function testRemovesOpenActionMarker(): void
    {
        $input = $this->tempDir . '/openaction.pdf';
        $output = $this->tempDir . '/openaction.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /OpenAction 2 0 R >> endobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString('/OpenAction', $clean);
    }

    public function testRemovesAdditionalActionsMarker(): void
    {
        $input = $this->tempDir . '/aa.pdf';
        $output = $this->tempDir . '/aa.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /AA << /O 2 0 R >> >> endobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString('/AA', $clean);
    }

    public function testStreamWithUnsupportedFilterIsPassedThroughUnscanned(): void
    {
        $input = $this->tempDir . '/unsupported.pdf';
        $output = $this->tempDir . '/unsupported.out.pdf';
        $body = 'irrelevant body bytes';
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Filter /Crypt /Length " . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringContainsString($body, $clean);
        self::assertFalse($report->metadataRemoved);
    }

    public function testStreamThatFailsToActuallyDecodeIsPassedThroughUnscanned(): void
    {
        $input = $this->tempDir . '/notreallycompressed.pdf';
        $output = $this->tempDir . '/notreallycompressed.out.pdf';
        $body = 'not really compressed data at all';
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringContainsString($body, $clean);
        self::assertFalse($report->metadataRemoved);
    }

    public function testStreamWithoutFilterIsPassedThroughUnscanned(): void
    {
        $input = $this->tempDir . '/nofilter.pdf';
        $output = $this->tempDir . '/nofilter.out.pdf';
        $body = 'plain unfiltered stream bytes';
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Length " . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringContainsString($body, $clean);
    }

    public function testNestedDictionaryBracesInStreamDictAreParsedCorrectly(): void
    {
        $input = $this->tempDir . '/nested.pdf';
        $output = $this->tempDir . '/nested.out.pdf';
        $hidden = '/JavaScript inside nested dict stream';
        $compressed = gzcompress($hidden);
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /DecodeParms << /Predictor 12 >> /Length "
            . strlen($compressed) . " >>\nstream\n" . $compressed . "\nendstream\nendobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString($compressed, $clean);
    }

    public function testStreamWithNoPrecedingDictionaryIsHandledWithoutCrashing(): void
    {
        $input = $this->tempDir . '/nodict.pdf';
        $output = $this->tempDir . '/nodict.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj\nstream\nplain body\nendstream\nendobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFalse($report->metadataRemoved);
    }

    public function testStreamExceedingBufferCapIsPassedThroughViaOverflow(): void
    {
        $input = $this->tempDir . '/big.pdf';
        $output = $this->tempDir . '/big.out.pdf';
        $body = str_repeat('A', 200);
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($body) . " >>\nstream\n"
            . $body . "\nendstream\nendobj\n%%EOF");

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output), ['streamBufferCap' => 10]))->sanitize($input, $output);

        $clean = (string) file_get_contents($output);
        self::assertStringContainsString($body, $clean);
    }

    /**
     * appendStreamBody() only writes through the cap-crossing split when $out is non-null, which
     * only happens during the real rewrite pass (the initial detection pass scans with $out=null).
     * A second, oversized-but-harmless stream is included purely so its cap overflow occurs during
     * that rewrite pass rather than the null-output detection pass.
     */
    public function testOversizedStreamDuringRewritePassIsSplitAcrossTheCapBoundary(): void
    {
        $hidden = gzcompress('/JavaScript trigger');
        $big = str_repeat('B', 300);
        $pdf = "%PDF-1.4\n"
            . "1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($hidden) . " >>\nstream\n" . $hidden . "\nendstream\nendobj\n"
            . "2 0 obj\n<< /Filter /FlateDecode /Length " . strlen($big) . " >>\nstream\n" . $big . "\nendstream\nendobj\n%%EOF";

        $input = $this->tempDir . '/two-streams.pdf';
        $output = $this->tempDir . '/two-streams.out.pdf';
        file_put_contents($input, $pdf);

        (new PdfSanitizer(new FileChunker($input), new FileWriter($output), ['streamBufferCap' => 100]))->sanitize($input, $output, true);

        $clean = (string) file_get_contents($output);
        self::assertStringContainsString($big, $clean);
    }

    /**
     * walkStreams()'s own chunk-read loop is fixed at a large internal buffer size, so a real file
     * small enough for tests is always read in a single call. A stream double that always delivers
     * short reads regardless of requested length is used to force the stream-keyword and
     * stream-body carry logic across multiple internal iterations deterministically.
     */
    public function testStreamKeywordAndBodySpanningManySmallReadsIsStillDetected(): void
    {
        $hidden = '/JavaScript trigger spanning many small reads';
        $compressed = gzcompress($hidden);
        $pdf = "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF";

        $input = $this->tempDir . '/chunked.pdf';
        $output = $this->tempDir . '/chunked.out.pdf';
        file_put_contents($input, $pdf);

        $stream = $this->shortReadStream($input);
        (new PdfSanitizer($stream, new FileWriter($output)))->sanitize($input, $output, true);

        $clean = (string) file_get_contents($output);
        self::assertStringNotContainsString($compressed, $clean);
    }

    public function testUnterminatedStreamAtEofIsStillFinished(): void
    {
        $input = $this->tempDir . '/unterminated.pdf';
        $output = $this->tempDir . '/unterminated.out.pdf';
        $body = 'irrelevant';
        file_put_contents($input, "%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode /Length " . strlen($body) . " >>\nstream\n" . $body);

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFalse($report->metadataRemoved);
        self::assertFileExists($output);
    }

    public function testUnbalancedClosingBracesInPrecedingTextFallsBackToRawWindow(): void
    {
        $input = $this->tempDir . '/orphan.pdf';
        $output = $this->tempDir . '/orphan.out.pdf';
        file_put_contents($input, "%PDF-1.4\n>> orphan closer\nstream\nbody\nendstream\nendobj\n%%EOF");

        $report = (new PdfSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFileExists($output);
        self::assertFalse($report->metadataRemoved);
    }

    /**
     * walkStreams()'s outer read loop has a defensive break for a stream implementation that
     * returns a false/empty read before eof() itself reports true. A real file-backed stream
     * cannot be made to do this reliably, so a stream double that always reports eof()=false is
     * used to force that specific path deterministically.
     */
    public function testWalkStreamsLoopStopsWhenStreamReturnsFalseBeforeReportingEof(): void
    {
        $input = $this->tempDir . '/lying-eof.pdf';
        $output = $this->tempDir . '/lying-eof.out.pdf';
        file_put_contents($input, "%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");

        $stream = new class ($input) implements StreamInterface
        {
            private FileChunker $inner;

            public function __construct(string $path)
            {
                $this->inner = new FileChunker($path);
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

        $report = (new PdfSanitizer($stream, new FileWriter($output)))->sanitize($input, $output);

        self::assertFalse($report->metadataRemoved);
    }

    private function shortReadStream(string $path): StreamInterface
    {
        return new class ($path) implements StreamInterface
        {
            private FileChunker $inner;

            public function __construct(string $path)
            {
                $this->inner = new FileChunker($path);
            }

            public function filePath(): string
            {
                return $this->inner->filePath();
            }

            public function read(int $length): false|string
            {
                return $this->inner->read(min(4, $length));
            }

            public function eof(): bool
            {
                return $this->inner->eof();
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
    }
}
