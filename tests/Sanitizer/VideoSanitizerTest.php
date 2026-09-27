<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

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
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertTrue($sanitizer->supports('video/mp4', 'video.mp4'));
        $this->assertTrue($sanitizer->supports('video/quicktime', 'video.mov'));
        $this->assertTrue($sanitizer->supports('video/webm', 'video.webm'));
        $this->assertTrue($sanitizer->supports('video/x-matroska', 'video.mkv'));
        $this->assertTrue($sanitizer->supports('video/x-msvideo', 'video.avi'));
    }

    public function testSupportsKnownVideoExtensionsWithGenericMime(): void
    {
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mp4'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mov'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.webm'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.mkv'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'video.avi'));
    }

    public function testDoesNotSupportUnknownFiles(): void
    {
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertFalse($sanitizer->supports('text/plain', 'note.txt'));
        $this->assertFalse($sanitizer->supports('application/pdf', 'file.pdf'));
        $this->assertFalse($sanitizer->supports('image/png', 'image.png'));
    }

    /**
     * libmagic falls back to application/octet-stream for huge amounts of unrelated binary or
     * control-byte-laden content, not just unrecognized video containers. Without a video
     * extension to corroborate it, that generic mimetype must not be claimed here — sanitize()
     * only knows how to dispatch by extension and would otherwise throw "Unsupported video type"
     * for arbitrary non-video content the resolver funneled to it.
     */
    public function testDoesNotSupportGenericOctetStreamWithoutAVideoExtension(): void
    {
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertFalse($sanitizer->supports('application/octet-stream', 'note.txt'));
        $this->assertFalse($sanitizer->supports('application/octet-stream', 'upload.bin'));
        $this->assertFalse($sanitizer->supports('application/octet-stream', 'noextension'));
    }

    public function testRemovesSuspiciousPayloadFromWebmLikeContainer(): void
    {
        $videoData = "\x1A\x45\xDF\xA3" . str_repeat("\x00", 32) . '<script>alert(1)</script>ok';

        $input = $this->writeTempFile('sample.webm', $videoData);
        $output = $this->tempPath('clean.webm');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

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

    public function testRemovesUdtaAtomFromMp4Container(): void
    {
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        $udta = pack('N', 16) . 'udta' . 'DEADBEEF';
        $mdat = pack('N', 8 + 7) . 'mdat' . 'ok-data';

        $input = $this->writeTempFile('sample.mp4', $ftyp . $udta . $mdat);
        $output = $this->tempPath('clean.mp4');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output, true);
        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertStringNotContainsString('DEADBEEF', $cleaned);
        $this->assertStringContainsString('ftyp', $cleaned);
        $this->assertStringContainsString('ok-data', $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('video_metadata_atom_removed', $codes);
    }

    public function testRemovesJunkChunkFromAviContainer(): void
    {
        $junk = 'JUNK' . pack('V', 8) . 'PADPADPA';
        $hdrl = 'hdrl' . pack('V', 8) . 'hdr-data';
        $body = 'AVI ' . $junk . $hdrl;
        $riff = 'RIFF' . pack('V', strlen($body)) . $body;

        $input = $this->writeTempFile('sample.avi', $riff);
        $output = $this->tempPath('clean.avi');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output, true);
        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertStringNotContainsString('PADPADPA', $cleaned);
        $this->assertStringContainsString('hdr-data', $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('avi_metadata_chunk_removed', $codes);
    }

    private function makeSanitizer(string $inputName, string $content): VideoSanitizer
    {
        $input = $this->writeTempFile($inputName, $content);
        $output = $this->tempPath('out-' . $inputName);
        return new VideoSanitizer(new FileChunker($input), new FileWriter($output));
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
