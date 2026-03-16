<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use Exception;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class TextLikeSanitizer implements SanitizerInterface
{
    private const TYPES = ['text/plain', 'text/csv', 'application/json', 'application/xml', 'text/xml'];

    public function supports(string $mimeType, string $path): bool
    {
        return in_array($mimeType, self::TYPES, true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $content = file_get_contents($inputPath);
        if ($content === false) {
            throw new RuntimeException('Could not read text-like file.');
        }
        $content = preg_replace('/^\xEF\xBB\xBF/', '', $content) ?? $content;
        $content = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $content) ?? $content;
        try {
            if (!file_exists(dirname($outputPath))) {
                mkdir(dirname($outputPath), 0755, true);
            }
        } catch (Exception $e) {
            throw new RuntimeException('Failed to create output directory: ' . $e->getMessage());
        }
        if (file_put_contents($outputPath, $content) === false) {
            throw new RuntimeException('Could not write sanitized text-like file.');
        }
        return new SanitizeReport($outputPath, false, [new Issue('text_normalized', 'Text-like content normalized by removing BOM and control characters.', IssueSeverity::Info)]);
    }
}
