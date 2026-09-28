<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Sanitizer\ImageSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class ImageSanitizerTest extends TestCase
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

    public function testSupportsKnownImageMimeTypes(): void
    {
        $input = $this->tempDir . '/input.png';
        $output = $this->tempDir . '/output.png';
        file_put_contents($input, 'placeholder');

        $sanitizer = new ImageSanitizer(new FileChunker($input), new FileWriter($output));

        self::assertTrue($sanitizer->supports('image/png', $input));
        self::assertTrue($sanitizer->supports('image/jpeg', $input));
        self::assertTrue($sanitizer->supports('image/gif', $input));
        self::assertTrue($sanitizer->supports('image/webp', $input));
        self::assertFalse($sanitizer->supports('text/plain', $input));
    }

    public function testReencodesPngAndStripsMetadata(): void
    {
        $input = $this->tempDir . '/input.png';
        $output = $this->tempDir . '/output.png';

        $image = imagecreatetruecolor(4, 4);
        imagepng($image, $input);
        imagedestroy($image);

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFileExists($output);
        self::assertSame(IMAGETYPE_PNG, exif_imagetype($output));
        self::assertNotEmpty($report->issues);
    }

    /**
     * A bad CRC on an ancillary (lowercase-initial) PNG chunk like tEXt makes libpng warn and
     * keep decoding rather than fail outright, which is exactly the case the installed error
     * handler exists to capture and surface as a png_metadata_warning Issue.
     */
    public function testPngDecodeWarningOnAncillaryChunkCrcErrorIsSurfacedAsIssue(): void
    {
        $input = $this->tempDir . '/warn.png';
        $output = $this->tempDir . '/warn.out.png';
        file_put_contents($input, $this->pngWithBadCrcTextChunk());

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $codes = array_map(static fn ($issue) => $issue->code, $report->issues);
        self::assertContains('png_metadata_warning', $codes);
    }

    public function testPngWithTextChunkMetadataIsReportedAsRemoved(): void
    {
        $input = $this->tempDir . '/meta.png';
        $output = $this->tempDir . '/meta.out.png';
        file_put_contents($input, $this->pngWithTextChunk());

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertTrue($report->metadataRemoved);
    }

    public function testJpegWithExifMarkerIsReencodedAndMetadataRemoved(): void
    {
        $input = $this->tempDir . '/meta.jpg';
        $output = $this->tempDir . '/meta.out.jpg';
        file_put_contents($input, $this->jpegWithExifComMarker());

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFileExists($output);
        self::assertSame(IMAGETYPE_JPEG, exif_imagetype($output));
        self::assertTrue($report->metadataRemoved);
    }

    public function testGifWithCommentExtensionIsReencodedAndMetadataRemoved(): void
    {
        $input = $this->tempDir . '/meta.gif';
        $output = $this->tempDir . '/meta.out.gif';
        file_put_contents($input, $this->gifWithCommentExtension());

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFileExists($output);
        self::assertSame(IMAGETYPE_GIF, exif_imagetype($output));
        self::assertTrue($report->metadataRemoved);
    }

    public function testWebpWithExifChunkIsReencodedAndMetadataRemoved(): void
    {
        $input = $this->tempDir . '/meta.webp';
        $output = $this->tempDir . '/meta.out.webp';
        file_put_contents($input, $this->webpWithExifChunk());

        $report = (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFileExists($output);
        self::assertSame(IMAGETYPE_WEBP, exif_imagetype($output));
        self::assertTrue($report->metadataRemoved);
    }

    public function testUnsupportedFileThrowsRuntimeException(): void
    {
        $input = $this->tempDir . '/not-an-image.png';
        $output = $this->tempDir . '/out.png';
        file_put_contents($input, 'this is not an image at all');

        $this->expectException(RuntimeException::class);
        (new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
    }

    public function testCreatesMissingOutputDirectory(): void
    {
        $input = $this->tempDir . '/input.png';
        $output = $this->tempDir . '/nested/deep/output.png';

        $image = imagecreatetruecolor(4, 4);
        imagepng($image, $input);
        imagedestroy($image);

        // No writer injected: ImageSanitizer ignores the DI stream/writer and works on the paths
        // directly via GD, so injecting a FileWriter here would create the directory itself first
        // and mask whether ImageSanitizer's own mkdir logic actually ran.
        (new ImageSanitizer(new FileChunker($input)))->sanitize($input, $output);

        self::assertFileExists($output);
    }

    /**
     * mkdir() raises a PHP warning (not just a false return) when the target already exists as a
     * regular file; it is suppressed here the same way it would be outside PHPUnit's strict
     * warning-to-exception handler, so ImageSanitizer's own failure guard is what's under test.
     * No FileWriter is injected for the output path: since ImageSanitizer never uses the injected
     * writer, constructing one for this same unreachable path would itself throw first (from
     * FileWriter's own constructor) and mask the guard actually being tested.
     */
    public function testThrowsWhenOutputDirectoryCannotBeCreated(): void
    {
        $input = $this->tempDir . '/input.png';
        $image = imagecreatetruecolor(4, 4);
        imagepng($image, $input);
        imagedestroy($image);

        $blocker = $this->tempDir . '/blocker';
        file_put_contents($blocker, 'i am a file, not a directory');
        $output = $blocker . '/sub/out.png';

        $this->expectException(RuntimeException::class);
        @(new ImageSanitizer(new FileChunker($input)))->sanitize($input, $output);
    }

    public function testCorruptPngThrowsRuntimeExceptionWithDecodeWarning(): void
    {
        $input = $this->tempDir . '/corrupt.png';
        $output = $this->tempDir . '/corrupt.out.png';
        // Valid 8-byte PNG signature followed by garbage: passes exif_imagetype() but not decoding.
        file_put_contents($input, "\x89PNG\r\n\x1a\n" . str_repeat("\x00", 20));

        $this->expectException(RuntimeException::class);
        @(new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
    }

    public function testCorruptJpegThrowsRuntimeException(): void
    {
        $input = $this->tempDir . '/corrupt.jpg';
        $output = $this->tempDir . '/corrupt.out.jpg';
        // Valid JPEG SOI marker followed by garbage: passes exif_imagetype() but not decoding.
        file_put_contents($input, "\xFF\xD8\xFF\xE0" . str_repeat("\x00", 20));

        $this->expectException(RuntimeException::class);
        @(new ImageSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
    }

    /**
     * Re-encoding fails when the output path is itself a directory; imagepng() can't open it for
     * writing. The @ suppresses the resulting PHP warning the same way it would be suppressed
     * outside PHPUnit's strict warning-to-exception handler. No FileWriter is injected: it is
     * unused by ImageSanitizer, and constructing one for this same directory path would itself
     * throw first from FileWriter's own constructor, masking the guard actually being tested.
     */
    public function testReencodeFailureThrowsRuntimeException(): void
    {
        $input = $this->tempDir . '/input.png';
        $image = imagecreatetruecolor(4, 4);
        imagepng($image, $input);
        imagedestroy($image);

        $outputAsDir = $this->tempDir . '/output-is-a-directory.png';
        mkdir($outputAsDir);

        $this->expectException(RuntimeException::class);
        @(new ImageSanitizer(new FileChunker($input)))->sanitize($input, $outputAsDir);
    }

    private function pngWithTextChunk(): string
    {
        $image = imagecreatetruecolor(4, 4);
        $tmp = $this->tempDir . '/_plain_' . bin2hex(random_bytes(4)) . '.png';
        imagepng($image, $tmp);
        imagedestroy($image);
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        $ihdrLen = unpack('N', substr($bytes, 8, 4))[1];
        $afterIhdr = 8 + 4 + 4 + $ihdrLen + 4;

        $textData = "Comment\x00hello";
        $crc = crc32('tEXt' . $textData);
        $textChunk = pack('N', strlen($textData)) . 'tEXt' . $textData . pack('N', $crc);

        return substr($bytes, 0, $afterIhdr) . $textChunk . substr($bytes, $afterIhdr);
    }

    private function pngWithBadCrcTextChunk(): string
    {
        $image = imagecreatetruecolor(4, 4);
        $tmp = $this->tempDir . '/_plain_' . bin2hex(random_bytes(4)) . '.png';
        imagepng($image, $tmp);
        imagedestroy($image);
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        $ihdrLen = unpack('N', substr($bytes, 8, 4))[1];
        $afterIhdr = 8 + 4 + 4 + $ihdrLen + 4;

        $textData = "Comment\x00hello";
        $badCrc = 0xDEADBEEF;
        $textChunk = pack('N', strlen($textData)) . 'tEXt' . $textData . pack('N', $badCrc);

        return substr($bytes, 0, $afterIhdr) . $textChunk . substr($bytes, $afterIhdr);
    }

    private function jpegWithExifComMarker(): string
    {
        $image = imagecreatetruecolor(4, 4);
        $tmp = $this->tempDir . '/_plain_' . bin2hex(random_bytes(4)) . '.jpg';
        imagejpeg($image, $tmp);
        imagedestroy($image);
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        $marker = "Exif\x00\x00" . str_repeat('X', 10);
        $com = "\xFF\xFE" . pack('n', strlen($marker) + 2) . $marker;

        return "\xFF\xD8" . $com . substr($bytes, 2);
    }

    private function gifWithCommentExtension(): string
    {
        $image = imagecreatetruecolor(4, 4);
        $tmp = $this->tempDir . '/_plain_' . bin2hex(random_bytes(4)) . '.gif';
        imagegif($image, $tmp);
        imagedestroy($image);
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        $commentData = 'Exif marker in gif';
        $commentBlock = "\x21\xFE" . chr(strlen($commentData)) . $commentData . "\x00";

        return substr($bytes, 0, -1) . $commentBlock . substr($bytes, -1);
    }

    private function webpWithExifChunk(): string
    {
        $image = imagecreatetruecolor(4, 4);
        $tmp = $this->tempDir . '/_plain_' . bin2hex(random_bytes(4)) . '.webp';
        imagewebp($image, $tmp);
        imagedestroy($image);
        $bytes = (string) file_get_contents($tmp);
        @unlink($tmp);

        $exifData = 'EXIF marker payload';
        $exifChunk = 'EXIF' . pack('V', strlen($exifData)) . $exifData;
        if (strlen($exifData) % 2 === 1) {
            $exifChunk .= "\x00";
        }

        $newBody = substr($bytes, 12) . $exifChunk;
        $newRiffSize = strlen($newBody) + 4;

        return 'RIFF' . pack('V', $newRiffSize) . 'WEBP' . $newBody;
    }
}
