<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
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
        // "a" + euro sign (3-byte UTF-8: \xE2\x82\xAC) + "b", with a 1-byte chunk size so the
        // euro sign's bytes are guaranteed to land in separate chunks.
        file_put_contents($input, "a\xE2\x82\xACb");

        (new TextLikeSanitizer(new FileChunker($input, 1), new FileWriter($output)))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertSame("a\xE2\x82\xACb", $clean);
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
