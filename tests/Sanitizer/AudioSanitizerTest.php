<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;

class AudioSanitizerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        parent::setUp();

        $this->tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'filesanitizer_audio_' . uniqid('', true);

        if (!is_dir($this->tempDir) && !mkdir($this->tempDir, 0777, true) && !is_dir($this->tempDir)) {
            throw new RuntimeException('Failed to create temp directory.');
        }
    }

    protected function tearDown(): void
    {
        $this->deleteDirectory($this->tempDir);
        parent::tearDown();
    }

    public function testSupportsKnownAudioMimeTypes(): void
    {
        $sanitizer = new AudioSanitizer();

        $this->assertTrue($sanitizer->supports('audio/mpeg', 'song.mp3'));
        $this->assertTrue($sanitizer->supports('audio/wav', 'sound.wav'));
        $this->assertTrue($sanitizer->supports('audio/ogg', 'voice.ogg'));
        $this->assertTrue($sanitizer->supports('audio/flac', 'track.flac'));
        $this->assertTrue($sanitizer->supports('audio/mp4', 'audio.m4a'));
        $this->assertTrue($sanitizer->supports('audio/aac', 'audio.aac'));
    }

    public function testSupportsKnownAudioExtensionsEvenIfMimeIsGeneric(): void
    {
        $sanitizer = new AudioSanitizer();

        $this->assertTrue($sanitizer->supports('application/octet-stream', 'song.mp3'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'sound.wav'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'voice.ogg'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'track.flac'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'audio.m4a'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'audio.aac'));
    }

    public function testDoesNotSupportUnknownFiles(): void
    {
        $sanitizer = new AudioSanitizer();

        $this->assertFalse($sanitizer->supports('text/plain', 'note.txt'));
        $this->assertFalse($sanitizer->supports('application/pdf', 'file.pdf'));
        $this->assertFalse($sanitizer->supports('image/png', 'image.png'));
    }

    public function testRemovesMp3Id3v1Tag(): void
    {
        $sanitizer = new AudioSanitizer();

        $audioData = str_repeat("\x00", 1024) . 'TAG' . str_repeat('A', 125);

        $input = $this->writeTempFile('sample.mp3', $audioData);
        $output = $this->tempPath('clean.mp3');

        $report = $sanitizer->sanitize($input, $output, true);

        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertSame(1024, strlen($cleaned));
        $this->assertNotSame('TAG', substr($cleaned, -128, 3));

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('mp3_id3v1_removed', $codes);
        $this->assertContains('audio_rewritten', $codes);
    }

    public function testRemovesMp3Id3v2Tag(): void
    {
        $sanitizer = new AudioSanitizer();

        $payload = str_repeat("\x11", 512);

        // ID3 header with syncsafe size 16 bytes: 00 00 00 10
        $id3Header = 'ID3' . "\x03\x00\x00" . "\x00\x00\x00\x10";
        $id3Body = str_repeat('M', 16);

        $audioData = $id3Header . $id3Body . $payload;

        $input = $this->writeTempFile('sample.mp3', $audioData);
        $output = $this->tempPath('clean.mp3');

        $report = $sanitizer->sanitize($input, $output, true);

        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertSame($payload, $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('mp3_id3v2_removed', $codes);
        $this->assertContains('audio_rewritten', $codes);
    }

    public function testRemovesSuspiciousTextualPayloadsFromOgg(): void
    {
        $sanitizer = new AudioSanitizer();

        $audioData = 'OggS' . str_repeat("\x00", 32) . '<script>alert(1)</script>ok';

        $input = $this->writeTempFile('sample.ogg', $audioData);
        $output = $this->tempPath('clean.ogg');

        $report = $sanitizer->sanitize($input, $output, true);

        $this->assertFileExists($output);

        $cleaned = file_get_contents($output);
        $this->assertIsString($cleaned);
        $this->assertStringNotContainsString('<script>', $cleaned);
        $this->assertStringContainsString('ok', $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('audio_textual_payload_removed', $codes);
        $this->assertContains('audio_rewritten', $codes);
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
