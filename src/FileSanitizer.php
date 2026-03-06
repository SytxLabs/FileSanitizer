<?php

namespace SytxLabs\FileSanitizer;

use SytxLabs\FileSanitizer\Exception\SanitizerException;
use SytxLabs\FileSanitizer\Sanitizers\BinarySanitizer;
use SytxLabs\FileSanitizer\Sanitizers\ImageSanitizer;
use SytxLabs\FileSanitizer\Sanitizers\OfficeOpenXmlSanitizer;
use SytxLabs\FileSanitizer\Sanitizers\PdfSanitizer;
use SytxLabs\FileSanitizer\Sanitizers\TextSanitizer;

class FileSanitizer
{
    public function sanitize(string $inputPath, ?string $outputPath = null): SanitizerResult
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("Input file not found or unreadable: {$inputPath}");
        }

        $mimeType = mime_content_type($inputPath) ?: 'application/octet-stream';
        $outputPath ??= $this->defaultOutputPath($inputPath);

        $sanitizer = $this->resolveSanitizer($mimeType, $inputPath);
        $sanitizerName = $sanitizer::class;

        $originalSize = filesize($inputPath);
        $originalHash = hash_file('sha256', $inputPath);

        $this->ensureDirectoryExists(dirname($outputPath));
        $sanitizer->sanitize($inputPath, $outputPath);

        $sanitizedSize = filesize($outputPath);
        $sanitizedHash = hash_file('sha256', $outputPath);

        return new SanitizerResult($inputPath, $outputPath, $mimeType, $sanitizerName, $originalSize ?: 0, $sanitizedSize ?: 0, $originalHash ?: '', $sanitizedHash ?: '');
    }

    private function resolveSanitizer(string $mimeType, string $inputPath): object
    {
        $extension = strtolower(pathinfo($inputPath, PATHINFO_EXTENSION));
        if ($mimeType === 'application/pdf' && !$this->looksLikePdf($inputPath)) {
            throw new SanitizerException('File claims to be a PDF but has no valid PDF header.');
        }
        return match (true) {
            $mimeType === 'application/pdf' => new PdfSanitizer(),

            str_starts_with($mimeType, 'image/') => new ImageSanitizer(),

            in_array($mimeType, [
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            ], true) => new OfficeOpenXmlSanitizer(),

            in_array($mimeType, ['text/plain', 'text/csv', 'application/json', 'text/json'], true),
            in_array($extension, ['txt', 'csv', 'json'], true) => new TextSanitizer(),
            default => new BinarySanitizer(),
        };
    }

    private function defaultOutputPath(string $inputPath): string
    {
        return dirname($inputPath) . DIRECTORY_SEPARATOR . pathinfo($inputPath, PATHINFO_FILENAME) . '.sanitized.' . pathinfo($inputPath, PATHINFO_EXTENSION);
    }

    private function ensureDirectoryExists(string $directory): void
    {
        if (is_dir($directory)) {
            return;
        }

        if (!mkdir($directory, 0777, true) && !is_dir($directory)) {
            throw new SanitizerException("Failed to create output directory: {$directory}");
        }
    }

    private function looksLikePdf(string $path): bool
    {
        $handle = fopen($path, 'rb');
        if ($handle === false) {
            return false;
        }

        $header = fread($handle, 8);
        fclose($handle);

        return is_string($header) && str_starts_with($header, '%PDF-');
    }
}
