<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
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

    public function testThrowsWhenStreamOrOutputNotInjected(): void
    {
        $input = $this->writeTempFile('sample.mp4', 'x');
        $output = $this->tempPath('out.mp4');

        $this->expectException(RuntimeException::class);
        (new VideoSanitizer())->sanitize($input, $output);
    }

    public function testThrowsForUnsupportedExtension(): void
    {
        $input = $this->writeTempFile('sample.xyz', 'x');
        $output = $this->tempPath('out.xyz');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $this->expectException(RuntimeException::class);
        $sanitizer->sanitize($input, $output);
    }

    public function testThrowsWhenStreamSizeCannotBeDetermined(): void
    {
        $input = $this->writeTempFile('sample.mp4', 'x');
        $output = $this->tempPath('out.mp4');

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

        $sanitizer = new VideoSanitizer($stream, new FileWriter($output));

        $this->expectException(RuntimeException::class);
        $sanitizer->sanitize($input, $output);
    }

    public function testCleanMp4WithNoSuspiciousPayloadOrMetadataAtomsHasNoExtraIssues(): void
    {
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        $mdat = pack('N', 8 + 7) . 'mdat' . 'ok-data';

        $input = $this->writeTempFile('clean.mp4', $ftyp . $mdat);
        $output = $this->tempPath('clean.out.mp4');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertNotContains('video_embedded_payload_detected', $codes);
        $this->assertNotContains('video_metadata_atom_removed', $codes);
    }

    public function testMp4WithSuspiciousEmbeddedPayloadIsFlagged(): void
    {
        $payload = 'javascript:alert(1)';
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        $mdat = pack('N', 8 + strlen($payload)) . 'mdat' . $payload;

        $input = $this->writeTempFile('payload.mp4', $ftyp . $mdat);
        $output = $this->tempPath('payload.out.mp4');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('video_embedded_payload_detected', $codes);
    }

    public function testMp4WithMalformedAtomSizeCopiesRemainderThroughUnchanged(): void
    {
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        // Declared atom size (4) is smaller than the 8-byte header itself: malformed.
        $malformed = pack('N', 4) . 'bad!' . 'trailing-bytes-kept-verbatim';

        $input = $this->writeTempFile('malformed.mp4', $ftyp . $malformed);
        $output = $this->tempPath('malformed.out.mp4');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $cleaned = (string) file_get_contents($output);
        $this->assertSame($ftyp . $malformed, $cleaned);
    }

    /**
     * The atom-header short-read guard protects against a stream whose declared size() promises
     * more bytes than the stream can actually deliver. A real FileChunker never disagrees with its
     * own filesize() like this, so a stream double that inflates size() beyond the real file's
     * length is used to force the loop to expect an atom header read() can no longer supply.
     */
    public function testMp4StopsWhenDeclaredSizeExceedsWhatTheStreamCanDeliver(): void
    {
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        $input = $this->writeTempFile('lying-size.mp4', $ftyp);
        $output = $this->tempPath('lying-size.out.mp4');

        $sanitizer = new VideoSanitizer($this->lyingSizeStream($input), new FileWriter($output));
        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    public function testAviPassesThroughUnchangedWhenNotARiffAviFile(): void
    {
        $videoData = 'not a real avi file, just plain bytes';

        $input = $this->writeTempFile('fake.avi', $videoData);
        $output = $this->tempPath('fake.out.avi');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertSame($videoData, (string) file_get_contents($output));
    }

    public function testAviChunkExceedingDeclaredSizeStopsScanningFurtherChunks(): void
    {
        $badChunk = 'JUNK' . pack('V', 999999);
        $body = 'AVI ' . $badChunk;
        $riff = 'RIFF' . pack('V', strlen($body)) . $body;

        $input = $this->writeTempFile('bad-size.avi', $riff);
        $output = $this->tempPath('bad-size.out.avi');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    /**
     * @see testMp4StopsWhenDeclaredSizeExceedsWhatTheStreamCanDeliver for why size() is inflated
     * rather than simulating truncation directly.
     */
    public function testAviStopsWhenDeclaredSizeExceedsWhatTheStreamCanDeliver(): void
    {
        $hdrl = 'hdrl' . pack('V', 8) . 'hdr-data';
        $body = 'AVI ' . $hdrl;
        $riff = 'RIFF' . pack('V', strlen($body)) . $body;

        $input = $this->writeTempFile('lying-size.avi', $riff);
        $output = $this->tempPath('lying-size.out.avi');

        $sanitizer = new VideoSanitizer($this->lyingSizeStream($input), new FileWriter($output));
        $sanitizer->sanitize($input, $output);

        $this->assertFileExists($output);
    }

    public function testAviNonDropChunkWithSuspiciousPayloadIsFlagged(): void
    {
        $payload = '<script>alert(1)</script>';
        $pad = strlen($payload) % 2 === 1 ? "\x00" : '';
        $movi = 'movi' . pack('V', strlen($payload)) . $payload . $pad;
        $body = 'AVI ' . $movi;
        $riff = 'RIFF' . pack('V', strlen($body)) . $body;

        $input = $this->writeTempFile('payload.avi', $riff);
        $output = $this->tempPath('payload.out.avi');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertContains('avi_embedded_payload_detected', $codes);
    }

    public function testAviNonDropChunkWithoutSuspiciousPayloadIsNotFlagged(): void
    {
        $hdrl = 'hdrl' . pack('V', 8) . 'hdr-data';
        $body = 'AVI ' . $hdrl;
        $riff = 'RIFF' . pack('V', strlen($body)) . $body;

        $input = $this->writeTempFile('nopayload.avi', $riff);
        $output = $this->tempPath('nopayload.out.avi');
        $sanitizer = new VideoSanitizer(new FileChunker($input), new FileWriter($output));

        $report = $sanitizer->sanitize($input, $output);

        $codes = $this->issueCodes($report->issues);
        $this->assertNotContains('avi_embedded_payload_detected', $codes);
    }

    private function lyingSizeStream(string $path): StreamInterface
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
