<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

class AudioSanitizer implements SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool
    {
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        return in_array($mimeType, ['audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/ogg', 'audio/flac', 'audio/mp4', 'audio/aac', 'audio/x-aac', ], true)
            || in_array($extension, ['mp3', 'wav', 'ogg', 'flac', 'm4a', 'aac', ], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $extension = strtolower((string) pathinfo($inputPath, PATHINFO_EXTENSION));

        $data = file_get_contents($inputPath);
        if ($data === false) {
            throw new RuntimeException('Could not read audio file.');
        }

        $directory = dirname($outputPath);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
                throw new RuntimeException('Failed to create output directory.');
            }
        }

        $issues = [];

        $sanitized = match ($extension) {
            'mp3' => $this->stripMp3Metadata($data, $issues),
            'wav' => $this->stripWavMetadata($data, $issues),
            'ogg', 'flac', 'm4a', 'aac' => $this->stripGenericTextualPayloads($data, $issues, $extension),
            default => throw new RuntimeException('Unsupported audio type.'),
        };
        if (file_put_contents($outputPath, $sanitized) === false) {
            throw new RuntimeException('Could not write sanitized audio file.');
        }
        $issues[] = new Issue('audio_rewritten', 'Audio file was rewritten or cleaned to reduce embedded metadata risk.', IssueSeverity::Info);
        return new SanitizeReport($outputPath, true, $issues);
    }

    private function stripMp3Metadata(string $data, array &$issues): string
    {
        $original = $data;

        if (strncmp($data, 'ID3', 3) === 0 && strlen($data) >= 10) {
            $size = $this->syncSafeInt(substr($data, 6, 4));
            $tagLength = 10 + $size;

            if ($tagLength > 0 && $tagLength < strlen($data)) {
                $data = substr($data, $tagLength);
                $issues[] = new Issue('mp3_id3v2_removed', 'Removed ID3v2 metadata.', IssueSeverity::Info);
            }
        }

        if (strlen($data) >= 128 && substr($data, -128, 3) === 'TAG') {
            $data = substr($data, 0, -128);
            $issues[] = new Issue('mp3_id3v1_removed', 'Removed ID3v1 metadata.', IssueSeverity::Info);
        }

        if (strlen($data) >= 32 && substr($data, -32, 8) === 'APETAGEX') {
            $issues[] = new Issue('mp3_ape_tag_detected', 'APEv2 tag detected; manual review recommended.', IssueSeverity::Warning);
        }
        return $data !== '' ? $data : $original;
    }

    private function stripWavMetadata(string $data, array &$issues): string
    {
        if (!str_starts_with($data, 'RIFF') || substr($data, 8, 4) !== 'WAVE') {
            return $data;
        }

        $output = substr($data, 0, 12);
        $offset = 12;
        $length = strlen($data);

        while ($offset + 8 <= $length) {
            $chunkId = substr($data, $offset, 4);
            $chunkSizeBytes = substr($data, $offset + 4, 4);
            if (strlen($chunkSizeBytes) !== 4) {
                break;
            }
            $chunkSize = unpack('V', $chunkSizeBytes)[1] ?? 0;
            $chunkDataEnd = ($offset + 8) + $chunkSize;
            if ($chunkDataEnd > $length) {
                break;
            }
            if (in_array($chunkId, ['LIST', 'INFO', 'id3 ', 'ID3 '], true)) {
                $issues[] = new Issue('wav_metadata_chunk_removed', 'Removed WAV metadata chunk: ' . trim($chunkId), IssueSeverity::Info);
            } else {
                $output .= substr($data, $offset, 8 + $chunkSize + ($chunkSize % 2));
            }

            $offset = $chunkDataEnd + ($chunkSize % 2);
        }

        $riffSize = strlen($output) - 8;
        return substr($output, 0, 4) . pack('V', $riffSize) . substr($output, 8);
    }

    private function stripGenericTextualPayloads(string $data, array &$issues, string $extension): string
    {
        $cleaned = preg_replace('#(?:<script\b.*?</script>|javascript:|<iframe\b.*?</iframe>|data\s*:\s*text/html|on[a-z0-9_-]+\s*=)#is', '', $data);
        if (!is_string($cleaned)) {
            return $data;
        }
        if ($cleaned !== $data) {
            $issues[] = new Issue('audio_textual_payload_removed', 'Removed suspicious embedded textual payloads from ' . $extension . ' container.', IssueSeverity::Warning);
        }
        return $cleaned;
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
