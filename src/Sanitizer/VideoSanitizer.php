<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Stream\ChunkedIoTrait;

/**
 * Streams the video file through fixed-size buffers rather than loading it whole, so a file far
 * larger than available memory does not crash the process — an MP4 "mdat" atom or a WebM/AVI
 * media chunk can be the entire file.
 */
class VideoSanitizer implements SanitizerInterface
{
    use ChunkedIoTrait;

    private const MP4_SUSPICIOUS_PATTERN = '#(?:<script\b|javascript:|on[a-z0-9_-]+\s*=|<iframe\b|data\s*:\s*text/html|<\?(?:php|=)?)#i';

    private const MATROSKA_STRIP_PATTERN = '#(?:<script\b.*?</script>|javascript:|<iframe\b.*?</iframe>|data\s*:\s*text/html|on[a-z0-9_-]+\s*=|<\?(?:php|=)?)#is';

    private const STRIP_OPEN_MARKERS = ['#<\s*script\b#i', '#<\s*iframe\b#i'];

    private const MP4_METADATA_ATOM_TYPES = ['udta', 'meta', 'ilst', 'XMP_'];

    private const AVI_DROP_CHUNK_IDS = ['INFO', 'JUNK', 'IDIT'];

    /** @param array<string, mixed>|null $options unused; accepted only to satisfy SanitizerInterface's constructor signature */
    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        return in_array($mimeType, ['video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska', 'video/x-msvideo'], true)
            || in_array($extension, ['mp4', 'mov', 'webm', 'mkv', 'avi'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        if ($this->stream === null || $this->output === null) {
            throw new RuntimeException('VideoSanitizer requires a stream and output to be injected via the constructor.');
        }

        $extension = strtolower((string) pathinfo($inputPath, PATHINFO_EXTENSION));

        $size = $this->stream->size();
        if ($size === false) {
            throw new RuntimeException('Could not read video file.');
        }

        $issues = [];
        $metadataRemoved = false;
        match ($extension) {
            'mp4', 'mov' => $this->sanitizeMp4Like($this->stream, $this->output, $size, $issues, $metadataRemoved),
            'webm', 'mkv' => $this->sanitizeMatroskaLike($this->stream, $this->output, $size, $issues, $extension, $metadataRemoved),
            'avi' => $this->sanitizeAvi($this->stream, $this->output, $size, $issues, $metadataRemoved),
            default => throw new RuntimeException('Unsupported video type.'),
        };

        $issues[] = new Issue('video_processed', 'Video file was processed with best-effort metadata and payload cleanup.', IssueSeverity::Info);
        return new SanitizeReport($outputPath, $metadataRemoved, $issues);
    }

    /** @param array<int, Issue> $issues */
    private function sanitizeMp4Like(StreamInterface $in, OutputInterface $out, int $size, array &$issues, bool &$metadataRemoved): void
    {
        $in->seek(0);
        $matched = $this->scanRangeForPatterns($in, $size, ['video_embedded_payload_detected' => self::MP4_SUSPICIOUS_PATTERN]);
        if ($matched !== []) {
            $issues[] = new Issue('video_embedded_payload_detected', 'Suspicious textual payload detected in MP4/MOV container.', IssueSeverity::Warning);
        }

        $in->seek(0);
        $removedCounts = array_fill_keys(self::MP4_METADATA_ATOM_TYPES, 0);
        $offset = 0;

        while ($offset + 8 <= $size) {
            $header = $this->readExact($in, 8);
            if (strlen($header) < 8) {
                break;
            }
            $atomSize = unpack('N', substr($header, 0, 4))[1] ?? 0;
            $type = substr($header, 4, 4);

            if ($atomSize < 8 || ($offset + $atomSize) > $size) {
                $out->write($header);
                $this->copyRange($in, $out, $size - ($offset + 8));
                return;
            }

            if (in_array($type, self::MP4_METADATA_ATOM_TYPES, true)) {
                $in->seek($offset + $atomSize);
                $removedCounts[$type]++;
            } else {
                $out->write($header);
                $this->copyRange($in, $out, $atomSize - 8);
            }
            $offset += $atomSize;
        }

        foreach (self::MP4_METADATA_ATOM_TYPES as $type) {
            if ($removedCounts[$type] > 0) {
                $issues[] = new Issue('video_metadata_atom_removed', 'Removed metadata atom: ' . $type, IssueSeverity::Info);
                $metadataRemoved = true;
            }
        }
    }

    /** @param array<int, Issue> $issues */
    private function sanitizeMatroskaLike(StreamInterface $in, OutputInterface $out, int $size, array &$issues, string $extension, bool &$metadataRemoved): void
    {
        $in->seek(0);
        $anyRemoved = false;
        $this->streamStripPatterns($in, $out, $size, self::MATROSKA_STRIP_PATTERN, self::STRIP_OPEN_MARKERS, $anyRemoved);
        if ($anyRemoved) {
            $issues[] = new Issue('video_textual_payload_removed', 'Removed suspicious embedded textual payloads from ' . $extension . ' container.', IssueSeverity::Warning);
            $metadataRemoved = true;
        }
    }

    /** @param array<int, Issue> $issues */
    private function sanitizeAvi(StreamInterface $in, OutputInterface $out, int $size, array &$issues, bool &$metadataRemoved): void
    {
        $in->seek(0);
        $header = $this->readExact($in, 12);
        if (strlen($header) < 12 || !str_starts_with($header, 'RIFF') || substr($header, 8, 4) !== 'AVI ') {
            $in->seek(0);
            $this->copyRange($in, $out, $size);
            return;
        }

        $keptBytes = 0;
        $offset = 12;
        while ($offset + 8 <= $size) {
            $chunkHeader = $this->readExact($in, 8);
            if (strlen($chunkHeader) < 8) {
                break;
            }
            $chunkId = substr($chunkHeader, 0, 4);
            $chunkSize = unpack('V', substr($chunkHeader, 4, 4))[1] ?? 0;
            $chunkTotal = 8 + $chunkSize + ($chunkSize % 2);
            if ($offset + $chunkTotal > $size) {
                break;
            }

            if (!in_array($chunkId, self::AVI_DROP_CHUNK_IDS, true)) {
                $keptBytes += $chunkTotal;
            }
            $in->seek($offset + $chunkTotal);
            $offset += $chunkTotal;
        }
        $out->write('RIFF' . pack('V', 4 + $keptBytes) . 'AVI ');
        $in->seek(12);
        $offset = 12;
        while ($offset + 8 <= $size) {
            $chunkHeader = $this->readExact($in, 8);
            if (strlen($chunkHeader) < 8) {
                break;
            }
            $chunkId = substr($chunkHeader, 0, 4);
            $chunkSize = unpack('V', substr($chunkHeader, 4, 4))[1] ?? 0;
            $chunkTotal = 8 + $chunkSize + ($chunkSize % 2);
            if ($offset + $chunkTotal > $size) {
                break;
            }

            if (in_array($chunkId, self::AVI_DROP_CHUNK_IDS, true)) {
                $in->seek($offset + $chunkTotal);
                $issues[] = new Issue('avi_metadata_chunk_removed', 'Removed AVI metadata chunk: ' . trim($chunkId), IssueSeverity::Info);
                $metadataRemoved = true;
            } else {
                $out->write($chunkHeader);
                $matched = false;
                $this->copyRangeWithPatternDetection($in, $out, $chunkSize + ($chunkSize % 2), '#(?:<script\b|javascript:|on[a-z0-9_-]+\s*=|<iframe\b|data\s*:\s*text/html)#i', $matched);
                if ($matched) {
                    $issues[] = new Issue('avi_embedded_payload_detected', 'Suspicious textual payload detected in AVI chunk.', IssueSeverity::Warning);
                }
            }
            $offset += $chunkTotal;
        }
    }
}
