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

class AudioSanitizer implements SanitizerInterface
{
    use ChunkedIoTrait;

    private const TEXTUAL_PAYLOAD_PATTERN = '#(?:<script\b.*?</script>|javascript:|<iframe\b.*?</iframe>|data\s*:\s*text/html|on[a-z0-9_-]+\s*=)#is';

    private const TEXTUAL_PAYLOAD_OPEN_MARKERS = ['#<\s*script\b#i', '#<\s*iframe\b#i'];

    /** @param array<string, mixed>|null $options unused; accepted only to satisfy SanitizerInterface's constructor signature */
    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        return in_array($mimeType, ['audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/ogg', 'audio/flac', 'audio/mp4', 'audio/aac', 'audio/x-aac'], true)
            || in_array($extension, ['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        if ($this->stream === null || $this->output === null) {
            throw new RuntimeException('AudioSanitizer requires a stream and output to be injected via the constructor.');
        }
        $extension = strtolower((string) pathinfo($inputPath, PATHINFO_EXTENSION));
        $size = $this->stream->size();
        if ($size === false) {
            throw new RuntimeException('Could not read audio file.');
        }

        $issues = [];
        $metadataRemoved = false;
        match ($extension) {
            'mp3' => $this->stripMp3Metadata($this->stream, $this->output, $size, $issues, $metadataRemoved),
            'wav' => $this->stripWavMetadata($this->stream, $this->output, $size, $issues, $metadataRemoved),
            'ogg', 'flac', 'm4a', 'aac' => $this->stripGenericTextualPayloads($this->stream, $this->output, $size, $issues, $extension, $metadataRemoved),
            default => throw new RuntimeException('Unsupported audio type.'),
        };
        $issues[] = new Issue('audio_rewritten', 'Audio file was rewritten or cleaned to reduce embedded metadata risk.', IssueSeverity::Info);
        return new SanitizeReport($outputPath, $metadataRemoved, $issues);
    }

    /** @param array<int, Issue> $issues */
    private function stripMp3Metadata(StreamInterface $in, OutputInterface $out, int $size, array &$issues, bool &$metadataRemoved): void
    {
        $bodyStart = 0;
        $header = $this->readExact($in, min(10, $size));
        if (strncmp($header, 'ID3', 3) === 0 && strlen($header) === 10) {
            $tagLength = 10 + $this->syncSafeInt(substr($header, 6, 4));
            if ($tagLength > 0 && $tagLength < $size) {
                $bodyStart = $tagLength;
                $issues[] = new Issue('mp3_id3v2_removed', 'Removed ID3v2 metadata.', IssueSeverity::Info);
                $metadataRemoved = true;
            }
        }

        $bodyEnd = $size;
        if ($size - $bodyStart >= 128) {
            $in->seek($size - 128);
            if (str_starts_with($this->readExact($in, 128), 'TAG')) {
                $bodyEnd = $size - 128;
                $issues[] = new Issue('mp3_id3v1_removed', 'Removed ID3v1 metadata.', IssueSeverity::Info);
                $metadataRemoved = true;
            }
        }

        if ($bodyEnd - $bodyStart >= 32) {
            $in->seek($bodyEnd - 32);
            if (str_starts_with($this->readExact($in, 32), 'APETAGEX')) {
                $issues[] = new Issue('mp3_ape_tag_detected', 'APEv2 tag detected; manual review recommended.', IssueSeverity::Warning);
            }
        }

        if ($bodyEnd <= $bodyStart) {
            $bodyStart = 0;
            $bodyEnd = $size;
        }

        $in->seek($bodyStart);
        $this->copyRange($in, $out, $bodyEnd - $bodyStart);
    }

    /** @param array<int, Issue> $issues */
    private function stripWavMetadata(StreamInterface $in, OutputInterface $out, int $size, array &$issues, bool &$metadataRemoved): void
    {
        $in->seek(0);
        $header = $this->readExact($in, 12);
        if (strlen($header) < 12 || !str_starts_with($header, 'RIFF') || substr($header, 8, 4) !== 'WAVE') {
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
            $chunkDataEnd = ($offset + 8) + $chunkSize;
            if ($chunkDataEnd > $size) {
                break;
            }
            $pad = $chunkSize % 2;

            if (!in_array($chunkId, ['LIST', 'INFO', 'id3 ', 'ID3 '], true)) {
                $keptBytes += 8 + $chunkSize + $pad;
            }
            $in->seek($chunkDataEnd + $pad);
            $offset = $chunkDataEnd + $pad;
        }
        $out->write('RIFF' . pack('V', 4 + $keptBytes) . 'WAVE');

        $in->seek(12);
        $offset = 12;
        while ($offset + 8 <= $size) {
            $chunkHeader = $this->readExact($in, 8);
            if (strlen($chunkHeader) < 8) {
                break;
            }
            $chunkId = substr($chunkHeader, 0, 4);
            $chunkSize = unpack('V', substr($chunkHeader, 4, 4))[1] ?? 0;
            $chunkDataEnd = ($offset + 8) + $chunkSize;
            if ($chunkDataEnd > $size) {
                break;
            }
            $pad = $chunkSize % 2;

            if (in_array($chunkId, ['LIST', 'INFO', 'id3 ', 'ID3 '], true)) {
                $in->seek($chunkDataEnd + $pad);
                $issues[] = new Issue('wav_metadata_chunk_removed', 'Removed WAV metadata chunk: ' . trim($chunkId), IssueSeverity::Info);
                $metadataRemoved = true;
            } else {
                $out->write($chunkHeader);
                $this->copyRange($in, $out, $chunkSize + $pad);
            }
            $offset = $chunkDataEnd + $pad;
        }
    }

    /** @param array<int, Issue> $issues */
    private function stripGenericTextualPayloads(StreamInterface $in, OutputInterface $out, int $size, array &$issues, string $extension, bool &$metadataRemoved): void
    {
        $in->seek(0);
        $anyRemoved = false;
        $this->streamStripPatterns($in, $out, $size, self::TEXTUAL_PAYLOAD_PATTERN, self::TEXTUAL_PAYLOAD_OPEN_MARKERS, $anyRemoved);
        if ($anyRemoved) {
            $issues[] = new Issue('audio_textual_payload_removed', 'Removed suspicious embedded textual payloads from ' . $extension . ' container.', IssueSeverity::Warning);
            $metadataRemoved = true;
        }
    }

    private function syncSafeInt(string $bytes): int
    {
        $parts = array_map('ord', str_split($bytes));
        if (count($parts) !== 4) {
            return 0;
        }
        return (($parts[0] & 0x7F) << 21) | (($parts[1] & 0x7F) << 14) | (($parts[2] & 0x7F) << 7) | ($parts[3] & 0x7F);
    }
}
