<?php

namespace SytxLabs\FileSanitizer;

use Exception;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\MimeDetectorInterface;
use SytxLabs\FileSanitizer\Contracts\NameSanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\MimeDetector\MimeDetector;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\HtmlSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\ImageSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\PdfSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\SvgSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\TextLikeSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;
use SytxLabs\FileSanitizer\Scanner\CompositeScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;
use SytxLabs\FileSanitizer\Stream\NullOutput;
use SytxLabs\FileSanitizer\Stream\NullStream;

final class FileSanitizer
{
    /** @var list<class-string<SanitizerInterface>> */
    private const DEFAULT_SANITIZER_CLASSES = [
        SvgSanitizer::class, HtmlSanitizer::class, ImageSanitizer::class, PdfSanitizer::class,
        TextLikeSanitizer::class, AudioSanitizer::class, VideoSanitizer::class,
    ];

    /** @var list<class-string<SanitizerInterface>|SanitizerInterface> */
    private array $sanitizerCandidates;

    /**
     * @param class-string<MimeDetectorInterface>|MimeDetectorInterface|null $mimeDetector
     * @param class-string<ScannerInterface>|ScannerInterface|null                 $scanner
     * @param class-string<StreamInterface>|StreamInterface|null                 $input
     * @param class-string<OutputInterface>|OutputInterface|null                 $output
     * @param list<class-string<SanitizerInterface>|SanitizerInterface>|null $sanitizerCandidates
     * @param class-string<NameSanitizerInterface>|NameSanitizerInterface|null $nameSanitizer
     */
    public function __construct(
        private readonly MimeDetectorInterface|string|null $mimeDetector = null,
        private readonly ScannerInterface|string|null $scanner = null,
        private readonly StreamInterface|string|null $input = null,
        private readonly OutputInterface|string|null $output = null,
        ?array $sanitizerCandidates = null,
        private readonly NameSanitizerInterface|string|null $nameSanitizer = null,
    ) {
        $this->sanitizerCandidates = $sanitizerCandidates ?? self::DEFAULT_SANITIZER_CLASSES;
    }

    public function scan(string $path, ?string $mimeType = null): ScanReport
    {
        if (!is_file($path)) {
            throw new RuntimeException(sprintf('Input file not found: %s', $path));
        }
        $mimeType ??= $this->buildInterface($this->mimeDetector, MimeDetectorInterface::class, MimeDetector::class)->detect($path);
        $scanStream = $this->buildInterface($this->input, StreamInterface::class, FileChunker::class, $path);
        try {
            return $this->buildInterface($this->scanner, ScannerInterface::class, CompositeScanner::class, $scanStream)->scan($path, $mimeType);
        } finally {
            $scanStream->close();
        }
    }

    /**
     * @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport}
     */
    public function process(string $inputPath, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        if (is_bool($outputPath)) {
            $sanitizeAlways = $outputPath;
            $outputPath = null;
        }

        if (!is_file($inputPath)) {
            throw new RuntimeException(sprintf('Input file not found: %s', $inputPath));
        }

        $mimeType ??= ($this->mimeDetector ?? new MimeDetector())->detect($inputPath);
        $scan = $this->scan($inputPath, $mimeType);
        $outputPath = $this->sanitizeOutputPath($outputPath ?? $this->defaultOutputPath($inputPath));
        if (!$scan->safe && !$sanitizeAlways) {
            return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => new SanitizeReport($outputPath, false, $scan->issues, ['skipped' => true])];
        }
        $resolved = $this->resolveSanitizer($mimeType, $inputPath);
        if ($resolved === null) {
            if (!copy($inputPath, $outputPath)) {
                throw new RuntimeException('Could not copy unsupported file to output path.');
            }
            $issues = $scan->issues;
            $issues[] = new Issue('no_sanitizer', 'No specialized sanitizer exists for this file type; original file was copied after scanning.', IssueSeverity::Warning);
            return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => $this->annotateUnchanged($scan, new SanitizeReport($outputPath, false, $issues, ['copied_original' => true]), $inputPath, true)];
        }

        if (is_string($resolved)) {
            $stream = $this->buildInterface($this->input, StreamInterface::class, FileChunker::class, $inputPath);
            $output = $this->buildInterface($this->output, OutputInterface::class, FileWriter::class, $outputPath);
            $sanitizer = new $resolved($stream, $output);
        } else {
            $sanitizer = $resolved;
            $stream = null;
            $output = null;
        }

        try {
            $sanitize = $sanitizer->sanitize($inputPath, $outputPath, $sanitizeAlways);
        } finally {
            $stream?->close();
            $output?->close();
        }

        if (!$scan->safe) {
            $sanitize = new SanitizeReport($sanitize->outputPath, $sanitize->metadataRemoved, [...$scan->issues, ...$sanitize->issues], [...$sanitize->context, 'sanitized_despite_scan_issues' => true]);
        }
        return ['mimeType' => $mimeType, 'scan' => $scan, 'sanitize' => $this->annotateUnchanged($scan, $sanitize, $inputPath)];
    }

    public function sanitizeAlways(string $inputPath, ?string $outputPath = null): array
    {
        return $this->process($inputPath, $outputPath, true);
    }

    /** @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string} */
    public function processString(string $data, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        return $this->processDataInput($data, $filenameHint, $outputPath, $sanitizeAlways, $mimeType);
    }

    /** @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string} */
    public function processBinary(string $binaryData, ?string $filenameHint = null, bool|string|null $outputPath = null, bool $sanitizeAlways = false, ?string $mimeType = null): array
    {
        return $this->processDataInput($binaryData, $filenameHint, $outputPath, $sanitizeAlways, $mimeType, false);
    }

    /** @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string, sanitizedBase64:string} */
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
        return [...$result, 'sanitizedBase64' => base64_encode($result['sanitizedData'])];
    }

    /** @return array{mimeType:string, scan:ScanReport, sanitize:SanitizeReport, sanitizedData:string} */
    private function processDataInput(string $data, ?string $filenameHint, bool|string|null $outputPath, bool $sanitizeAlways, ?string $mimeType, bool $normalizeStringLiterals = true): array
    {
        if (is_bool($outputPath)) {
            $sanitizeAlways = $outputPath;
            $outputPath = null;
        }
        $normalizedData = $normalizeStringLiterals ? $this->normalizeStringInput($data) : $data;
        $resolvedMimeType = $mimeType ?? $this->detectMimeTypeFromData($normalizedData);
        $inputPath = $this->createTempInputPath($filenameHint, $resolvedMimeType);
        if (file_put_contents($inputPath, $normalizedData) === false) {
            throw new RuntimeException('Could not write temporary input file for string processing.');
        }
        $result = null;
        try {
            $result = $this->process($inputPath, $outputPath, $sanitizeAlways, $resolvedMimeType);
            return [...$result, 'sanitizedData' => $this->readFileIfExists($result['sanitize']->outputPath)];
        } finally {
            $this->safeUnlink($inputPath);
            if (!is_string($outputPath) && $result !== null && is_file($result['sanitize']->outputPath)) {
                $this->safeUnlink($result['sanitize']->outputPath);
                $this->cleanupEmptyDir(dirname($result['sanitize']->outputPath));
            }
            $this->cleanupEmptyDir(dirname($inputPath));
        }
    }

    private function createTempInputPath(?string $filenameHint, ?string $mimeType): string
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
        $safeName = $this->sanitizeName($filenameHint ?? ('upload' . ($fallbackExtension !== null ? '.' . $fallbackExtension : '.bin')));
        if ($safeName === 'file') {
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
        return (preg_match('/^b([\"\'])(.*)\1$/is', trim($data), $matches) !== 1) ? $data : stripcslashes($matches[2]);
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

    public function sanitizeName(string $filename): string
    {
        return $this->buildInterface($this->nameSanitizer, NameSanitizerInterface::class, NameSanitizer::class)->sanitize($filename);
    }

    private function buildInterface(mixed $value, string $interface, string $default, mixed ...$args): mixed
    {
        return $value instanceof $interface ? $value : new ($value ?? $default)(...$args);
    }

    /** @return class-string<SanitizerInterface>|SanitizerInterface|null */
    private function resolveSanitizer(string $mimeType, string $path): SanitizerInterface|string|null
    {
        foreach ($this->sanitizerCandidates as $candidate) {
            if ($candidate instanceof SanitizerInterface) {
                if ($candidate->supports($mimeType, $path)) {
                    return $candidate;
                }
                continue;
            }
            if ((new $candidate(new NullStream($path), new NullOutput($path)))->supports($mimeType, $path)) {
                return $candidate;
            }
        }
        return null;
    }

    private function annotateUnchanged(ScanReport $scan, SanitizeReport $sanitize, string $inputPath, bool $knownUnchanged = false): SanitizeReport
    {
        if (!($knownUnchanged || $this->filesAreIdentical($inputPath, $sanitize->outputPath))) {
            return $sanitize;
        }
        $issues = $sanitize->issues;
        if ($scan->safe) {
            $issues[] = new Issue('sanitizer_no_changes', 'No changes were necessary; the file was already safe.', IssueSeverity::Info);
        }
        return new SanitizeReport($sanitize->outputPath, $sanitize->metadataRemoved, $issues, $sanitize->context, unchanged: true);
    }

    private function filesAreIdentical(string $a, string $b): bool
    {
        if (!is_file($a) || !is_file($b) || filesize($a) !== filesize($b)) {
            return false;
        }
        return hash_equals((string) hash_file('sha256', $a), (string) hash_file('sha256', $b));
    }

    private function defaultOutputPath(string $inputPath): string
    {
        $extension = pathinfo($inputPath, PATHINFO_EXTENSION);
        if ($extension === '') {
            return $inputPath . '.sanitized';
        }
        return substr($inputPath, 0, -strlen($extension) - 1) . '.sanitized.' . $extension;
    }

    private function sanitizeOutputPath(string $outputPath): string
    {
        $directory = dirname($outputPath);
        $safeName = $this->sanitizeName(basename($outputPath));
        return $directory === '.' ? $safeName : $directory . DIRECTORY_SEPARATOR . $safeName;
    }
}
