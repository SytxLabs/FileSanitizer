<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Sanitizer\TextLikeSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class TextLikeSanitizerTest extends TestCase
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

    public function testRemovesBomAndControlCharacters(): void
    {
        $input = $this->tempDir . '/input.txt';
        $output = $this->tempDir . '/output.txt';
        file_put_contents($input, "\xEF\xBB\xBFhello\x00world\x1F!");

        (new TextLikeSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertSame('helloworld!', $clean);
    }

    public function testPreservesMultiByteUtf8CharacterSplitAcrossAChunkBoundary(): void
    {
        $input = $this->tempDir . '/input.txt';
        $output = $this->tempDir . '/output.txt';
        // "a" + euro sign (3-byte UTF-8: \xE2\x82\xAC) + "b", with a 1-byte sanitizer bufferSize
        // (not FileChunker's own chunkSize, which only affects its unused chunks()/readAll()
        // helpers) so the euro sign's bytes are guaranteed to land in separate read() calls.
        file_put_contents($input, "a\xE2\x82\xACb");

        (new TextLikeSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 1]))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertSame("a\xE2\x82\xACb", $clean);
    }

    public function testSupportsKnownTextLikeMimeTypes(): void
    {
        $sanitizer = new TextLikeSanitizer();

        self::assertTrue($sanitizer->supports('text/plain', '/tmp/x.txt'));
        self::assertTrue($sanitizer->supports('text/csv', '/tmp/x.csv'));
        self::assertTrue($sanitizer->supports('application/json', '/tmp/x.json'));
        self::assertTrue($sanitizer->supports('application/xml', '/tmp/x.xml'));
        self::assertTrue($sanitizer->supports('text/xml', '/tmp/x.xml'));
        self::assertFalse($sanitizer->supports('image/png', '/tmp/x.png'));
    }

    public function testUsesDefaultStreamAndWriterWhenNoneInjected(): void
    {
        $input = $this->tempDir . '/default.txt';
        $output = $this->tempDir . '/default.out.txt';
        file_put_contents($input, "hello\x00world");

        $report = (new TextLikeSanitizer())->sanitize($input, $output);

        self::assertSame('helloworld', (string) file_get_contents($output));
        self::assertSame($output, $report->outputPath);
    }

    public function testPreservesTwoByteUtf8CharacterSplitAcrossAChunkBoundary(): void
    {
        $input = $this->tempDir . '/two-byte.txt';
        $output = $this->tempDir . '/two-byte.out.txt';
        // "a" + e-acute (2-byte UTF-8: \xC3\xA9) + "b".
        file_put_contents($input, "a\xC3\xA9b");

        (new TextLikeSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 1]))->sanitize($input, $output);

        self::assertSame("a\xC3\xA9b", (string) file_get_contents($output));
    }

    public function testPreservesFourByteUtf8CharacterSplitAcrossAChunkBoundary(): void
    {
        $input = $this->tempDir . '/four-byte.txt';
        $output = $this->tempDir . '/four-byte.out.txt';
        // "a" + grinning face emoji (4-byte UTF-8: \xF0\x9F\x98\x80) + "b".
        file_put_contents($input, "a\xF0\x9F\x98\x80b");

        (new TextLikeSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 1]))->sanitize($input, $output);

        self::assertSame("a\xF0\x9F\x98\x80b", (string) file_get_contents($output));
    }

    /**
     * A file that ends mid-sequence (an incomplete multi-byte UTF-8 lead) leaves a pending carry
     * that the main loop never gets to resolve, since no further bytes ever arrive; it must still
     * be flushed once the loop exits at EOF rather than silently dropped.
     */
    public function testTruncatedMultiByteSequenceAtEofIsStillFlushed(): void
    {
        $input = $this->tempDir . '/truncated.txt';
        $output = $this->tempDir . '/truncated.out.txt';
        // "a" followed by the first two bytes of a 3-byte euro sign, with no third byte ever.
        file_put_contents($input, "a\xE2\x82");

        (new TextLikeSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame("a\xE2\x82", (string) file_get_contents($output));
    }

    /**
     * The main read loop has a defensive break for a stream implementation that returns a
     * false/empty read before eof() itself reports true. A real file-backed stream cannot be made
     * to do this reliably, so a stream double that always reports eof()=false is used to force
     * that specific path deterministically.
     */
    public function testLoopStopsWhenStreamReturnsFalseBeforeReportingEof(): void
    {
        $input = $this->tempDir . '/lying-eof.txt';
        $output = $this->tempDir . '/lying-eof.out.txt';
        file_put_contents($input, 'hello world');

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

        (new TextLikeSanitizer($stream, new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('hello world', (string) file_get_contents($output));
    }

    public function testHandlesFileLargerThanChunkSize(): void
    {
        $input = $this->tempDir . '/input.txt';
        $output = $this->tempDir . '/output.txt';
        $content = str_repeat('abc', 1000);
        file_put_contents($input, $content);

        (new TextLikeSanitizer(new FileChunker($input, 7), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame($content, file_get_contents($output));
    }
}
