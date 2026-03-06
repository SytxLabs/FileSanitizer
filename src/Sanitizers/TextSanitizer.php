<?php

namespace SytxLabs\FileSanitizer\Sanitizers;

use SytxLabs\FileSanitizer\Exception\SanitizerException;

class TextSanitizer
{
    public function sanitize(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("Text file not found or unreadable: {$inputPath}");
        }

        $content = file_get_contents($inputPath);

        if ($content === false) {
            throw new SanitizerException("Failed to read text file: {$inputPath}");
        }

        $normalized = mb_convert_encoding($content, 'UTF-8', 'UTF-8');

        if (file_put_contents($outputPath, $normalized) === false) {
            throw new SanitizerException("Failed to write sanitized text file: {$outputPath}");
        }
    }
}
