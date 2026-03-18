<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\DTO\Issue;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;

class VideoSanitizerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'filesanitizer_video_' . uniqid('', true);
        if (!is_dir($this->tempDir) && !mkdir($this->tempDir, 0777, true) && !is_dir($this->tempDir)) {
            throw new RuntimeException('Failed to create temp directory.');
        }
    }

    protected function tearDown(): void
    {
        $this->deleteDirectory($this->tempDir);
        parent::tearDown();
    }

    public function testSupportsKnownVideoMimeTypes(): void
    {
        $sanitizer = new VideoSanitizer();

        $this->assertTrue($sanitizer->supports('video/mp4', 'video.mp4'));
        $this->assertTrue($sanitizer->supports('video/quicktime', 'video.mov'));
        $this->assertTrue($sanitizer->supports('video/webm', 'video.webm'));
        $this->assertTrue($sanitizer->supports('video/x-matroska', 'video.mkv'));
        $this->assertTrue($sanitizer->supports('video/x-msvideo', 'video.avi'));
    }

    public function testSupportsKnownVideoExtensionsWithGenericMime(): void
    {
        $sanitizer = new VideoSanitizer();

        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mp4'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mov'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.webm'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mkv'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.avi'));
    }

    public function testDoesNotSupportUnknownFiles(): void
    {
        $sanitizer = new VideoSanitizer();

        $this->assertFalse($sanitizer->supports('text/plain', 'note.txt'));
        $this->assertFalse($sanitizer->supports('application/pdf', 'file.pdf'));
        $this->assertFalse($sanitizer->supports('image/png', 'image.png'));
    }

    public function testRemovesSuspiciousPayloadFromWebmLikeContainer(): void
    {
        $sanitizer = new VideoSanitizer();

        $videoData = "\x1A\x45\xDF\xA3" . str_repeat("\x00", 32) . '<script>alert(1)</script>ok';

        $input = $this->writeTempFile('sample.webm', $videoData);
        $output = $this->tempPath('clean.webm');

        $report = $sanitizer->sanitize($input, $output, true);
        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertStringNotContainsString('<script>', $cleaned);
        $this->assertStringContainsString('ok', $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('video_textual_payload_removed', $codes);
        $this->assertContains('video_processed', $codes);
    }

    private function writeTempFile(string $name, string $content): string
    {
        $path = $this->tempPath($name);
        if (file_put_contents($path, $content) === false) {
            throw new RuntimeException('Failed to write temp file.');
        }
        return $path;
    }

    private function tempPath(string $name): string
    {
        return $this->tempDir . DIRECTORY_SEPARATOR . $name;
    }

    /**
     * @param array<int, Issue> $issues
     *
     * @return array<int, string>
     */
    private function issueCodes(array $issues): array
    {
        return array_map(static fn (Issue $issue): string => $issue->code, $issues);
    }

    private function deleteDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }
        $items = scandir($directory);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $path = $directory . DIRECTORY_SEPARATOR . $item;
            if (is_dir($path)) {
                $this->deleteDirectory($path);
            } else {
                @unlink($path);
            }
        }
        @rmdir($directory);
    }
}
