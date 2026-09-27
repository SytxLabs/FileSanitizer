<?php

namespace SytxLabs\FileSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\FileSanitizer;

/**
 * Covers processString()/processBinary()/processBase64(): the data-input convenience methods that
 * restore parity with the Laravel wrapper (sytxlabs/laravel-filesanitizer), which calls these on
 * BaseFileSanitizer directly with no method_exists() guard.
 */
final class FileSanitizerDataInputTest extends TestCase
{
    public function testProcessStringSanitizesPlainTextData(): void
    {
        $fileSanitizer = new FileSanitizer();

        // No control bytes: libmagic classifies any buffer containing one as application/octet-stream
        // outright regardless of surrounding text, which this library's resolver then routes to
        // AudioSanitizer/VideoSanitizer as a "maybe an unrecognized container" guess (pre-existing
        // routing quirk, unrelated to this method — control-byte stripping itself is covered by
        // TextLikeSanitizerTest and NameSanitizerTest).
        $result = $fileSanitizer->processString('hello world, this is plain text content for sniffing.', 'note.txt');

        self::assertSame('text/plain', $result['mimeType']);
        self::assertTrue($result['scan']->safe);
        self::assertSame('hello world, this is plain text content for sniffing.', $result['sanitizedData']);
    }

    public function testProcessStringUnwrapsBLiteralWrapper(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processString("b'hello world'", 'note.txt');

        self::assertSame('hello world', $result['sanitizedData']);
    }

    public function testProcessBinaryDoesNotUnwrapBLiteralWrapper(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processBinary("b'hello world'", 'note.txt');

        self::assertSame("b'hello world'", $result['sanitizedData']);
    }

    public function testProcessBase64RoundTripsSanitizedContent(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processBase64(base64_encode('plain text content long enough to sniff as text.'), 'note.txt');

        self::assertSame('plain text content long enough to sniff as text.', $result['sanitizedData']);
        self::assertSame(base64_encode('plain text content long enough to sniff as text.'), $result['sanitizedBase64']);
    }

    public function testProcessBase64AcceptsDataUriAndUsesItsMimeType(): void
    {
        $fileSanitizer = new FileSanitizer();

        $dataUri = 'data:text/plain;base64,' . base64_encode('hello');
        $result = $fileSanitizer->processBase64($dataUri, 'note.txt');

        self::assertSame('text/plain', $result['mimeType']);
        self::assertSame('hello', $result['sanitizedData']);
    }

    public function testProcessBase64RejectsInvalidPayload(): void
    {
        $fileSanitizer = new FileSanitizer();

        $this->expectException(\RuntimeException::class);
        $fileSanitizer->processBase64('not valid base64!!!', 'note.txt');
    }

    public function testExplicitMimeTypeOverridesContentSniffing(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processString('plain text content', 'note.bin', mimeType: 'text/plain');

        self::assertSame('text/plain', $result['mimeType']);
    }

    public function testFilenameHintWithTraversalIsSanitizedForTheTempFile(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processString('hello world, this is plain text.', '../../etc/passwd');

        self::assertStringContainsString('passwd', $result['sanitize']->outputPath);
        self::assertStringNotContainsString('..', $result['sanitize']->outputPath);
    }

    /**
     * A null byte makes libmagic classify the buffer as application/octet-stream outright,
     * regardless of the surrounding text. Before the VideoSanitizer routing fix, that generic
     * mimetype was matched unconditionally and the resolver sent this straight to VideoSanitizer,
     * which threw "Unsupported video type" since sanitize() only actually handles known video
     * extensions. It must now fall through to the no-sanitizer path (original copied through, with
     * a warning issue) instead of crashing.
     */
    public function testAmbiguousBinaryContentFallsBackGracefullyInsteadOfCrashing(): void
    {
        $fileSanitizer = new FileSanitizer();

        $result = $fileSanitizer->processString("hello\x00world", 'note.txt');

        self::assertSame('application/octet-stream', $result['mimeType']);
        self::assertSame("hello\x00world", $result['sanitizedData']);
        $codes = array_map(static fn ($issue) => $issue->code, $result['sanitize']->issues);
        self::assertContains('no_sanitizer', $codes);
    }

    public function testWritesToExplicitOutputPathAndLeavesItOnDisk(): void
    {
        $tempDir = sys_get_temp_dir() . '/fsz_datainput_test_' . bin2hex(random_bytes(6));
        mkdir($tempDir, 0777, true);
        $outputPath = $tempDir . '/kept.txt';

        try {
            $fileSanitizer = new FileSanitizer();
            $result = $fileSanitizer->processString('hello world', 'note.txt', $outputPath);

            self::assertFileExists($outputPath);
            self::assertSame('hello world', file_get_contents($outputPath));
            // Separator may be normalized to DIRECTORY_SEPARATOR by sanitizeOutputPath(); compare
            // the resolved real path instead of the literal string.
            self::assertSame(realpath($outputPath), realpath($result['sanitize']->outputPath));
        } finally {
            @unlink($outputPath);
            @rmdir($tempDir);
        }
    }
}
