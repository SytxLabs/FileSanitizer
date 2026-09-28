<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

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
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertTrue($sanitizer->supports('audio/mpeg', 'song.mp3'));
        $this->assertTrue($sanitizer->supports('audio/wav', 'sound.wav'));
        $this->assertTrue($sanitizer->supports('audio/ogg', 'voice.ogg'));
        $this->assertTrue($sanitizer->supports('audio/flac', 'track.flac'));
        $this->assertTrue($sanitizer->supports('audio/mp4', 'audio.m4a'));
        $this->assertTrue($sanitizer->supports('audio/aac', 'audio.aac'));
    }

    public function testSupportsKnownAudioExtensionsEvenIfMimeIsGeneric(): void
    {
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertTrue($sanitizer->supports('application/octet-stream', 'song.mp3'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'sound.wav'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'voice.ogg'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'track.flac'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'audio.m4a'));
        $this->assertTrue($sanitizer->supports('application/octet-stream', 'audio.aac'));
    }

    public function testDoesNotSupportUnknownFiles(): void
    {
        $sanitizer = $this->makeSanitizer('probe.bin', 'x');

        $this->assertFalse($sanitizer->supports('text/plain', 'note.txt'));
        $this->assertFalse($sanitizer->supports('application/pdf', 'file.pdf'));
        $this->assertFalse($sanitizer->supports('image/png', 'image.png'));
    }

    public function testRemovesMp3Id3v1Tag(): void
    {
        $audioData = str_repeat("\x00", 1024) . 'TAG' . str_repeat('A', 125);

        $input = $this->writeTempFile('sample.mp3', $audioData);
        $output = $this->tempPath('clean.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

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
        $payload = str_repeat("\x11", 512);

        // ID3 header with syncsafe size 16 bytes: 00 00 00 10
        $id3Header = 'ID3' . "\x03\x00\x00" . "\x00\x00\x00\x10";
        $id3Body = str_repeat('M', 16);

        $audioData = $id3Header . $id3Body . $payload;

        $input = $this->writeTempFile('sample.mp3', $audioData);
        $output = $this->tempPath('clean.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

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
        $audioData = 'OggS' . str_repeat("\x00", 32) . '<script>alert(1)</script>ok';

        $input = $this->writeTempFile('sample.ogg', $audioData);
        $output = $this->tempPath('clean.ogg');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

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

    public function testThrowsWhenStreamOrOutputNotInjected(): void
    {
        $input = $this->writeTempFile('sample.mp3', 'x');
        $output = $this->tempPath('out.mp3');

        $this->expectException(RuntimeException::class);
        (new AudioSanitizer())->sanitize($input, $output);
    }

    public function testThrowsForUnsupportedExtension(): void
    {
        $input = $this->writeTempFile('sample.xyz', 'x');
        $output = $this->tempPath('out.xyz');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $this->expectException(RuntimeException::class);
        $sanitizer->sanitize($input, $output);
    }

    public function testThrowsWhenStreamSizeCannotBeDetermined(): void
    {
        $input = $this->writeTempFile('sample.mp3', 'x');
        $output = $this->tempPath('out.mp3');

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

        $sanitizer = new AudioSanitizer($stream, new FileWriter($output));

        $this->expectException(RuntimeException::class);
        $sanitizer->sanitize($input, $output);
    }

    public function testDetectsApeTagWithoutRemovingIt(): void
    {
        $audioData = str_repeat("\x00", 512) . 'APETAGEX' . str_repeat("\x01", 24);

        $input = $this->writeTempFile('ape.mp3', $audioData);
        $output = $this->tempPath('ape.out.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('mp3_ape_tag_detected', $codes);
    }

    /**
     * An ID3 header whose declared tag length is not smaller than the file itself is treated as
     * bogus and left alone, rather than stripping "metadata" that would consume the entire body.
     */
    public function testIgnoresId3HeaderWithImplausibleTagLength(): void
    {
        // Syncsafe size bytes 7F 7F 7F 7F decode to a huge length, far larger than the file.
        $id3Header = 'ID3' . "\x03\x00\x00" . "\x7F\x7F\x7F\x7F";
        $audioData = $id3Header . str_repeat('M', 50);

        $input = $this->writeTempFile('bogus-id3.mp3', $audioData);
        $output = $this->tempPath('bogus-id3.out.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertNotContains('mp3_id3v2_removed', $codes);
        $this->assertSame($audioData, (string) file_get_contents($output));
    }

    public function testSmallMp3FileSkipsId3v1Check(): void
    {
        $audioData = str_repeat("\x11", 50);

        $input = $this->writeTempFile('small.mp3', $audioData);
        $output = $this->tempPath('small.out.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $this->assertSame($audioData, (string) file_get_contents($output));
        $codes = $this->issueCodes($report->issues);
        $this->assertNotContains('mp3_id3v1_removed', $codes);
    }

    public function testWavPassesThroughUnchangedWhenNotARiffWaveFile(): void
    {
        $audioData = 'not a real wav file, just plain bytes';

        $input = $this->writeTempFile('fake.wav', $audioData);
        $output = $this->tempPath('fake.out.wav');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertSame($audioData, (string) file_get_contents($output));
    }

    public function testWavStripsListInfoMetadataChunkAndKeepsAudioData(): void
    {
        $fmtChunk = 'fmt ' . pack('V', 16) . str_repeat("\x00", 16);
        $listData = 'INFO' . 'IART' . pack('V', 4) . 'Bob0';
        $listChunk = 'LIST' . pack('V', strlen($listData)) . $listData;
        $dataChunk = 'data' . pack('V', 8) . str_repeat("\x7F", 8);
        $body = $fmtChunk . $listChunk . $dataChunk;
        $audioData = 'RIFF' . pack('V', 4 + strlen($body)) . 'WAVE' . $body;

        $input = $this->writeTempFile('meta.wav', $audioData);
        $output = $this->tempPath('meta.out.wav');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $cleaned = (string) file_get_contents($output);
        $this->assertStringNotContainsString('LIST', $cleaned);
        $this->assertStringNotContainsString('Bob0', $cleaned);
        $this->assertStringContainsString('fmt ', $cleaned);
        $this->assertStringContainsString('data', $cleaned);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('wav_metadata_chunk_removed', $codes);
    }

    public function testWavWithOddSizedChunkIsPaddedCorrectly(): void
    {
        // An odd-length "data" chunk needs a single pad byte per the RIFF spec.
        $dataChunk = 'data' . pack('V', 3) . 'ABC' . "\x00";
        $audioData = 'RIFF' . pack('V', 4 + strlen($dataChunk)) . 'WAVE' . $dataChunk;

        $input = $this->writeTempFile('odd.wav', $audioData);
        $output = $this->tempPath('odd.out.wav');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertSame($audioData, (string) file_get_contents($output));
    }

    public function testWavStopsOnTruncatedChunkHeader(): void
    {
        $audioData = 'RIFF' . pack('V', 4 + 4) . 'WAVE' . 'dat';

        $input = $this->writeTempFile('trunc-header.wav', $audioData);
        $output = $this->tempPath('trunc-header.out.wav');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    public function testWavStopsOnChunkSizeExceedingRemainingFile(): void
    {
        $badChunk = 'data' . pack('V', 999999);
        $audioData = 'RIFF' . pack('V', 4 + strlen($badChunk)) . 'WAVE' . $badChunk;

        $input = $this->writeTempFile('bad-size.wav', $audioData);
        $output = $this->tempPath('bad-size.out.wav');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    /**
     * When the ID3v2 tag extends right up to the trailing ID3v1 tag, the computed body window
     * collapses to zero (bodyEnd <= bodyStart); the sanitizer then falls back to keeping the whole
     * original file rather than writing an inverted/empty range.
     */
    public function testMp3WithNoRemainingBodyFallsBackToOriginalFile(): void
    {
        // Syncsafe-encoded 162: bytes [0,0,1,34] decode to (1<<7)|34 = 162.
        $id3Header = 'ID3' . "\x03\x00\x00" . "\x00\x00\x01\x22";
        $id3Body = str_repeat('M', 162);
        $trailer = 'TAG' . str_repeat('A', 125);
        $audioData = $id3Header . $id3Body . $trailer;
        $this->assertSame(300, strlen($audioData));

        $input = $this->writeTempFile('collapsed.mp3', $audioData);
        $output = $this->tempPath('collapsed.out.mp3');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $this->assertSame($audioData, (string) file_get_contents($output));
        $codes = $this->issueCodes($report->issues);
        $this->assertContains('mp3_id3v2_removed', $codes);
        $this->assertContains('mp3_id3v1_removed', $codes);
    }

    /**
     * The chunk-header short-read guard protects against a stream whose declared size() promises
     * more bytes than the stream can actually deliver. A real FileChunker never disagrees with its
     * own filesize() like this, so a stream double that inflates size() beyond the real file's
     * length is used to force the loop arithmetic to expect a chunk header that read() can no
     * longer supply, in both scan passes.
     */
    public function testWavStopsWhenDeclaredSizeExceedsWhatTheStreamCanDeliver(): void
    {
        $fmtChunk = 'fmt ' . pack('V', 16) . str_repeat("\x00", 16);
        $audioData = 'RIFF' . pack('V', 4 + strlen($fmtChunk)) . 'WAVE' . $fmtChunk;
        $input = $this->writeTempFile('lying-size.wav', $audioData);
        $output = $this->tempPath('lying-size.out.wav');

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
                return $this->inner->eof();
            }

            public function tell(): false|int
            {
                return $this->inner->tell();
            }

            public function size(): false|int
            {
                $real = $this->inner->size();
                return $real === false ? false : $real + 100;
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

        $sanitizer = new AudioSanitizer($stream, new FileWriter($output));
        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    public function testCleanOggFileHasNoTextualPayloadIssue(): void
    {
        $audioData = 'OggS' . str_repeat("\x00", 32) . 'just normal audio bytes';

        $input = $this->writeTempFile('clean.ogg', $audioData);
        $output = $this->tempPath('clean.out.ogg');
        $sanitizer = new AudioSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertNotContains('audio_textual_payload_removed', $codes);
    }

    private function makeSanitizer(string $inputName, string $content): AudioSanitizer
    {
        $input = $this->writeTempFile($inputName, $content);
        $output = $this->tempPath('out-' . $inputName);
        return new AudioSanitizer(new FileChunker($input), new FileWriter($output));
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
