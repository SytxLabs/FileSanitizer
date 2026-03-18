<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

class VideoSanitizer implements SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool
    {
        $extension = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        return in_array($mimeType, ['video/mp4', 'video/quicktime', 'video/webm', 'video/x-matroska', 'video/x-msvideo', 'application/octet-stream'], true)
            || in_array($extension, ['mp4', 'mov', 'webm', 'mkv', 'avi'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $extension = strtolower((string) pathinfo($inputPath, PATHINFO_EXTENSION));
        $data = file_get_contents($inputPath);
        if ($data === false) {
            throw new RuntimeException('Could not read video file.');
        }
        $directory = dirname($outputPath);
        if (!is_dir($directory)) {
            if (!mkdir($directory, 0755, true) && !is_dir($directory)) {
                throw new RuntimeException('Failed to create output directory.');
            }
        }
        $issues = [];
        $sanitized = match ($extension) {
            'mp4', 'mov' => $this->sanitizeMp4Like($data, $issues),
            'webm', 'mkv' => $this->sanitizeMatroskaLike($data, $issues, $extension),
            'avi' => $this->sanitizeAvi($data, $issues),
            default => throw new RuntimeException('Unsupported video type.'),
        };
        if (file_put_contents($outputPath, $sanitized) === false) {
            throw new RuntimeException('Could not write sanitized video file.');
        }
        $issues[] = new Issue('video_processed', 'Video file was processed with best-effort metadata and payload cleanup.', IssueSeverity::Info);
        return new SanitizeReport($outputPath, true, $issues);
    }

    private function sanitizeMp4Like(string $data, array &$issues): string
    {
        $cleaned = $data;
        $suspiciousPatterns = ['#<script\b#i', '#javascript:#i', '#on[a-z0-9_-]+\s*=#i', '#<iframe\b#i', '#data\s*:\s*text/html#i', '#<\?(?:php|=)?#i'];
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $cleaned) === 1) {
                $issues[] = new Issue('video_embedded_payload_detected', 'Suspicious textual payload detected in MP4/MOV container.', IssueSeverity::Warning);
                break;
            }
        }
        foreach (['udta', 'meta', 'ilst', 'XMP_'] as $atom) {
            $updated = $this->stripIsoBmffAtoms($cleaned, $atom, $removed);
            if ($removed > 0) {
                $issues[] = new Issue('video_metadata_atom_removed', 'Removed metadata atom: ' . $atom, IssueSeverity::Info);
                $cleaned = $updated;
            }
        }
        return $cleaned;
    }

    private function sanitizeMatroskaLike(string $data, array &$issues, string $extension): string
    {
        $cleaned = preg_replace('#(?:<script\b.*?</script>|javascript:|<iframe\b.*?</iframe>|data\s*:\s*text/html|on[a-z0-9_-]+\s*=|<\?(?:php|=)?)#is', '', $data);
        if (!is_string($cleaned)) {
            return $data;
        }
        if ($cleaned !== $data) {
            $issues[] = new Issue('video_textual_payload_removed', 'Removed suspicious embedded textual payloads from ' . $extension . ' container.', IssueSeverity::Warning);
        }
        return $cleaned;
    }

    private function sanitizeAvi(string $data, array &$issues): string
    {
        if (!str_starts_with($data, 'RIFF') || substr($data, 8, 4) !== 'AVI ') {
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
            $chunkTotal = 8 + $chunkSize + ($chunkSize % 2);
            if ($offset + $chunkTotal > $length) {
                break;
            }
            $drop = in_array($chunkId, ['INFO', 'JUNK', 'IDIT'], true);
            if ($drop) {
                $issues[] = new Issue('avi_metadata_chunk_removed', 'Removed AVI metadata chunk: ' . trim($chunkId), IssueSeverity::Info);
            } else {
                $chunk = substr($data, $offset, $chunkTotal);
                if (preg_match('#(?:<script\b|javascript:|on[a-z0-9_-]+\s*=|<iframe\b|data\s*:\s*text/html)#i', $chunk) === 1) {
                    $issues[] = new Issue('avi_embedded_payload_detected', 'Suspicious textual payload detected in AVI chunk.', IssueSeverity::Warning);
                }
                $output .= $chunk;
            }
            $offset += $chunkTotal;
        }
        $riffSize = strlen($output) - 8;
        return substr($output, 0, 4) . pack('V', $riffSize) . substr($output, 8);
    }

    private function stripIsoBmffAtoms(string $data, string $targetAtom, ?int &$removed = 0): string
    {
        $removed = 0;
        $offset = 0;
        $length = strlen($data);
        $output = '';

        while ($offset + 8 <= $length) {
            $sizeData = substr($data, $offset, 4);
            $type = substr($data, $offset + 4, 4);
            if (strlen($sizeData) !== 4 || strlen($type) !== 4) {
                break;
            }
            $size = unpack('N', $sizeData)[1] ?? 0;
            if ($size < 8 || ($offset + $size) > $length) {
                $output .= substr($data, $offset);
                return $output;
            }
            $atom = substr($data, $offset, $size);
            if ($type === $targetAtom) {
                $removed++;
            } else {
                $output .= $atom;
            }
            $offset += $size;
        }
        if ($offset < $length) {
            $output .= substr($data, $offset);
        }
        return $output === '' ? $data : $output;
    }
}
