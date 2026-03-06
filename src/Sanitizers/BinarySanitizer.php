<?php

namespace SytxLabs\FileSanitizer\Sanitizers;

use SytxLabs\FileSanitizer\Exception\SanitizerException;

class BinarySanitizer
{
    public function sanitize(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("File not found or unreadable: {$inputPath}");
        }
        if (!copy($inputPath, $outputPath)) {
            throw new SanitizerException("Failed to copy file to: {$outputPath}");
        }
    }
}
