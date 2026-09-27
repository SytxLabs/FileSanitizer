<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
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
}
