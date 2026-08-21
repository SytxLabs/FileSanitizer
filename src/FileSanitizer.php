<?php

namespace SytxLabs\FileSanitizer;

use Exception;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\HtmlSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\ImageSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\PdfSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\SvgSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\TextLikeSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;
use SytxLabs\FileSanitizer\Scanner\PatternScanner;
use SytxLabs\FileSanitizer\Support\MimeDetector;

final class FileSanitizer
{
    /** @var list<SanitizerInterface> */
    private array $sanitizers;

    public function __construct(private readonly ?MimeDetector $mimeDetector = null, private readonly ?ScannerInterface $scanner = null, ?array $sanitizers = null)
    {
        $this->sanitizers = $sanitizers ?? [new SvgSanitizer(), new HtmlSanitizer(), new ImageSanitizer(), new PdfSanitizer(), new TextLikeSanitizer(), new AudioSanitizer(), new VideoSanitizer()];
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport}
     */
    public function process(string $inputPath, bool|string|null $outputPath = null, bool $sanitizeAlways = false): array
    {
        if (is_bool($outputPath)) {
            $sanitizeAlways = $outputPath;
            $outputPath = null;
        }

        if (!is_file($inputPath)) {
            throw new RuntimeException(sprintf('Input file not found: %s', $inputPath));
        }

        $mimeType = ($this->mimeDetector ?? new MimeDetector())->detect($inputPath);

        return $this->processWithMimeType($inputPath, $mimeType, $outputPath, $sanitizeAlways);
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport}
     * @noinspection PhpUnused
     */
    public function sanitizeAlways(string $inputPath, ?string $outputPath = null): array
    {
        return $this->process($inputPath, $outputPath, true);
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string}
     */
    public function processString(string $data, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        return $this->processDataInput($data, $filenameHint, $outputPath, $sanitizeAlways, $mimeType);
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string}
     */
    public function processBinary(string $binaryData, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        return $this->processDataInput($binaryData, $filenameHint, $outputPath, $sanitizeAlways, $mimeType, false);
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string}
     */
    private function processDataInput(string $data, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null, bool $normalizeStringLiterals = true): array
    {
        if (is_bool($outputPath)) {
            $sanitizeAlways = $outputPath;
            $outputPath = null;
        }
        $normalizedData = $normalizeStringLiterals ? $this->normalizeStringInput($data) : $data;
        $resolvedMimeType = $mimeType ?? $this->detectMimeTypeFromData($normalizedData);
        $inputPath = $this->createTempInputPath($filenameHint, $resolvedMimeType);
        $result = null;
        if (file_put_contents($inputPath, $normalizedData) === false) {
            throw new RuntimeException('Could not write temporary input file for string processing.');
        }
        try {
            $result = $this->processWithMimeType($inputPath, $resolvedMimeType, $outputPath, $sanitizeAlways);
            $sanitizedData = $this->readFileIfExists($result['sanitize']->outputPath);
            return [...$result, 'sanitizedData' => $sanitizedData];
        } finally {
            $this->safeUnlink($inputPath);
            if (!is_string($outputPath) && isset($result['sanitize']) && is_file($result['sanitize']->outputPath)) {
                $this->safeUnlink($result['sanitize']->outputPath);
                $this->cleanupEmptyDir(dirname($result['sanitize']->outputPath));
            }
            $this->cleanupEmptyDir(dirname($inputPath));
        }
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string, sanitizedBase64:string}
     */
    public function processBase64(string $base64Data, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        if (is_bool($outputPath)) {
            $sanitizeAlways = $outputPath;
            $outputPath = null;
        }
        $decoded = base64_decode($this->extractBase64Payload($base64Data), true);
        if ($decoded === false) {
            throw new RuntimeException('Invalid base64 input.');
        }
        $result = $this->processBinary($decoded, $filenameHint, $outputPath, $sanitizeAlways, $mimeType ?? $this->extractDataUriMimeType($base64Data));
        return [...$result, 'sanitizedBase64' => 'data:' . $result['mimeType'] . ';base64,' . base64_encode($result['sanitizedData'])];
    }

    private function resolveSanitizer(string $mimeType, string $path): ?SanitizerInterface
    {
        foreach ($this->sanitizers as $sanitizer) {
            if ($sanitizer->supports($mimeType, $path)) {
                return $sanitizer;
            }
        }
        return null;
    }

    private function defaultOutputPath(string $inputPath): string
    {
        $extension = pathinfo($inputPath, PATHINFO_EXTENSION);
        return substr($inputPath, 0, -strlen($extension) - ($extension !== '' ? 1 : 0)) . '.sanitized' . ($extension !== '' ? '.' . $extension : '');
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport}
     */
    private function processWithMimeType(string $inputPath, string $mimeType, bool|string|null $outputPath = null, bool $sanitizeAlways = false): array
    {
        $scan = ($this->scanner ?? new PatternScanner())->scan($inputPath, $mimeType);
        $outputPath ??= $this->defaultOutputPath($inputPath);
        if (!$scan->safe && !$sanitizeAlways) {
            return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => new SanitizeReport($outputPath, false, $scan->issues, ['skipped' => true])];
        }
        $sanitizer = $this->resolveSanitizer($mimeType, $inputPath);
        if ($sanitizer === null) {
            if (!copy($inputPath, $outputPath)) {
                throw new RuntimeException('Could not copy unsupported file to output path.');
            }
            $issues = $scan->issues;
            $issues[] = new Issue('no_sanitizer', 'No specialized sanitizer exists for this file type; original file was copied after scanning.', IssueSeverity::Warning);
            return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => new SanitizeReport($outputPath, false, $issues, ['copied_original' => true])];
        }
        $sanitize = $sanitizer->sanitize($inputPath, $outputPath, $sanitizeAlways);
        if (!$scan->safe) {
            $sanitize = new SanitizeReport($sanitize->outputPath, $sanitize->metadataRemoved, [...$scan->issues, ...$sanitize->issues], [...$sanitize->context, 'sanitized_despite_scan_issues' => true]);
        }
        return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => $sanitize];
    }

    private function createTempInputPath(?string $filenameHint = null, ?string $mimeType = null): string
    {
        $fallbackExtension = match (strtolower($mimeType ?? '')) {
            'text/html' => 'html',
            'application/xhtml+xml' => 'xhtml',
            'image/svg+xml' => 'svg',
            'application/json' => 'json',
            'application/xml', 'text/xml' => 'xml',
            'text/plain' => 'txt',
            'application/pdf' => 'pdf',
            'image/jpeg' => 'jpg',
            'image/png' => 'png',
            'image/gif' => 'gif',
            'image/webp' => 'webp',
            'application/zip' => 'zip',
            default => null,
        };
        $hint = $filenameHint ?? ('upload' . ($fallbackExtension !== null ? '.' . $fallbackExtension : '.bin'));
        $safeName = trim(preg_replace('/[^A-Za-z0-9._-]/', '_', basename($hint)) ?? 'upload.bin');
        if ($safeName === '' || $safeName === '.' || $safeName === '..') {
            $safeName = 'upload' . ($fallbackExtension !== null ? '.' . $fallbackExtension : '.bin');
        }
        try {
            $tempDirectory = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fsz_data_' . bin2hex(random_bytes(8));
        } catch (Exception $e) {
            throw new RuntimeException('Could not generate random directory name for string processing.', previous: $e);
        }
        if (!mkdir($tempDirectory, 0755, true) && !is_dir($tempDirectory)) {
            throw new RuntimeException('Could not create temporary directory for string processing.');
        }
        return $tempDirectory . DIRECTORY_SEPARATOR . $safeName;
    }

    private function extractBase64Payload(string $base64Data): string
    {
        $trimmed = trim($base64Data);
        if (preg_match('#^data:[^;]+;base64,(.+)$#is', $trimmed, $matches) === 1) {
            $trimmed = $matches[1];
        }
        return preg_replace('/\s+/', '', $trimmed) ?? $trimmed;
    }

    private function extractDataUriMimeType(string $base64Data): ?string
    {
        if (preg_match('#^\s*data:([^;,\s]+);base64,#i', $base64Data, $matches) !== 1) {
            return null;
        }
        $mimeType = strtolower(trim($matches[1]));
        return $mimeType !== '' ? $mimeType : null;
    }

    private function detectMimeTypeFromData(string $data): string
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo !== false) {
            $detected = finfo_buffer($finfo, $data);
            finfo_close($finfo);
            if (is_string($detected) && $detected !== '' && $detected !== 'application/octet-stream') {
                return strtolower(trim($detected));
            }
        }
        $trimmed = ltrim($data);
        return match (true) {
            preg_match('/^%PDF-/i', $trimmed) === 1 => 'application/pdf',
            preg_match('/^<!DOCTYPE\s+svg\b/i', $trimmed) === 1 || preg_match('/^<svg\b/i', $trimmed) === 1 => 'image/svg+xml',
            preg_match('/^<\?xml\b/i', $trimmed) === 1 => 'application/xml',
            preg_match('/^<html\b/i', $trimmed) === 1 || preg_match('/^<!doctype\s+html\b/i', $trimmed) === 1 => 'text/html',
            preg_match('/^\s*[{\[]/', $trimmed) === 1 => 'application/json',
            default => 'application/octet-stream',
        };
    }

    private function normalizeStringInput(string $data): string
    {
        if (preg_match('/^b([\"\'])(.*)\1$/is', trim($data), $matches) !== 1) {
            return $data;
        }
        return stripcslashes($matches[2]);
    }

    private function readFileIfExists(string $path): string
    {
        if (!is_file($path)) {
            return '';
        }
        $content = file_get_contents($path);
        return $content !== false ? $content : throw new RuntimeException(sprintf('Could not read output file: %s', $path));
    }

    private function safeUnlink(string $path): void
    {
        if (is_file($path)) {
            @unlink($path);
        }
    }

    private function cleanupEmptyDir(string $directory): void
    {
        if (is_dir($directory) && count(scandir($directory) ?: []) === 2) {
            @rmdir($directory);
        }
    }
}
