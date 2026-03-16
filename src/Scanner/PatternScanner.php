<?php

declare(strict_types=1);

namespace SytxLabs\FileSanitizer\Scanner;

use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use ZipArchive;

final class PatternScanner implements ScannerInterface
{
    public function __construct(
        private readonly int $maxArchiveDepth = 3,
        private readonly int $maxArchiveEntries = 1000,
        private readonly int $maxExpandedBytes = 25000000,
    ) {
    }

    public function scan(string $path, string $mimeType): ScanReport
    {
        $issues = [];
        $content = @file_get_contents($path);

        if ($content === false) {
            return ScanReport::unsafe([
                new Issue('read_failed', 'The file could not be read for scanning.', IssueSeverity::Error),
            ]);
        }

        $patterns = [
            'xss_script_tag' => '/<\s*script\b/i',
            'xss_javascript_url' => '/javascript\s*:/i',
            'xss_data_html' => '/data\s*:\s*text\/html/i',
            'xss_inline_handler' => '/on(?:load|error|click|mouseover|focus|submit|pointerdown)\s*=/i',
            'xss_eval' => '/\beval\s*\(/i',
            'xss_function_ctor' => '/\b(?:new\s+function\s*\(|function\s*\(|new\s+Function\s*\()/i',
            'dom_sink' => '/(?:innerhtml|outerhtml|document\.write|insertadjacenthtml)\b/i',
            'cookie_access' => '/document\.cookie/i',
            'iframe_embed' => '/<\s*iframe\b/i',
            'svg_foreignobject' => '/<\s*foreignobject\b/i',
            'svg_animate' => '/<\s*animate\b/i',
            'php_tag' => '/<\?(?:php|=)?/i',
            'php_exec' => '/\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\(/i',
            'pdf_js' => '/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/AA\b/i',
            'html_meta_refresh' => '/<meta[^>]+http-equiv\s*=\s*["\']?refresh/i',
            'html_base_tag' => '/<\s*base\b/i',
            'css_expression' => '/expression\s*\(/i',
            'css_import' => '/@import\b/i',
        ];

        foreach ($patterns as $code => $pattern) {
            if (preg_match($pattern, $content) === 1) {
                $issues[] = new Issue($code, sprintf('Suspicious pattern detected: %s', $code), IssueSeverity::Error);
            }
        }

        if (str_starts_with($mimeType, 'image/svg') && preg_match('/<\s*(?:script|iframe|embed|object|foreignObject|animate|set)\b/i', $content) === 1) {
            $issues[] = new Issue('svg_active_content', 'SVG contains active or externally-referential content elements.', IssueSeverity::Error);
        }

        if ($this->isArchiveMimeType($mimeType, $path)) {
            $issues = [...$issues, ...$this->scanArchive($path, 0, basename($path), 0)];
        }

        return $issues === [] ? ScanReport::clean() : ScanReport::unsafe($issues);
    }

    private function isArchiveMimeType(string $mimeType, string $path): bool
    {
        return in_array($mimeType, [
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/zip',
        ], true) || str_ends_with(strtolower($path), '.zip');
    }

    /** @return list<Issue> */
    private function scanArchive(string $path, int $depth, string $displayName, int $expandedBytes): array
    {
        if ($depth > $this->maxArchiveDepth) {
            return [new Issue('archive_depth_exceeded', sprintf('Archive nesting depth exceeded while scanning "%s".', $displayName), IssueSeverity::Warning)];
        }

        $zip = new ZipArchive();
        if ($zip->open($path) !== true) {
            return [new Issue('archive_open_failed', sprintf('Archive "%s" could not be opened for deep scanning.', $displayName), IssueSeverity::Warning)];
        }

        $issues = [];
        $entryCount = min($zip->numFiles, $this->maxArchiveEntries);
        if ($zip->numFiles > $this->maxArchiveEntries) {
            $issues[] = new Issue('archive_entry_limit', sprintf('Archive "%s" exceeded entry scan limit; scan truncated.', $displayName), IssueSeverity::Warning);
        }

        for ($i = 0; $i < $entryCount; $i++) {
            $stat = $zip->statIndex($i);
            $name = (string) ($zip->getNameIndex($i) ?: '');
            $normalizedName = strtolower(str_replace('\\', '/', $name));
            $entryPath = $displayName . '::' . $name;

            if ($normalizedName === '' || str_ends_with($normalizedName, '/')) {
                continue;
            }

            if ($this->isPathTraversal($normalizedName)) {
                $issues[] = new Issue('archive_path_traversal', sprintf('Archive entry has suspicious path traversal markers: "%s".', $entryPath), IssueSeverity::Error);
            }

            $entry = $zip->getFromIndex($i);
            if ($entry === false) {
                $issues[] = new Issue('archive_entry_read_failed', sprintf('Archive entry could not be read: "%s".', $entryPath), IssueSeverity::Warning);
                continue;
            }

            $expandedBytes += strlen($entry);
            if ($expandedBytes > $this->maxExpandedBytes) {
                $issues[] = new Issue('archive_size_limit', sprintf('Expanded archive scan size exceeded while scanning "%s".', $displayName), IssueSeverity::Warning);
                break;
            }

            if (str_contains($normalizedName, 'vbaproject.bin')) {
                $issues[] = new Issue('office_macro', sprintf('Embedded VBA macro detected in "%s".', $entryPath), IssueSeverity::Error);
            }
            if (str_contains($normalizedName, 'activex') || str_contains($normalizedName, 'oleobject')) {
                $issues[] = new Issue('office_activex', sprintf('Embedded ActiveX or OLE object detected in "%s".', $entryPath), IssueSeverity::Error);
            }
            if (str_ends_with($normalizedName, '.rels') && preg_match('/TargetMode="External"/i', $entry) === 1) {
                $issues[] = new Issue('office_external_reference', sprintf('External relationship detected in "%s".', $entryPath), IssueSeverity::Warning);
            }
            if (preg_match('#(?:javascript:|<script\b|on[a-z0-9_-]+\s*=|document\.cookie|<iframe\b|data\s*:\s*text/html)#i', $entry) === 1) {
                $issues[] = new Issue('archive_embedded_script', sprintf('Suspicious script-like content detected in "%s".', $entryPath), IssueSeverity::Error);
            }

            if ($this->looksLikeZip($normalizedName, $entry, $stat['size'] ?? null)) {
                $nestedPath = tempnam(sys_get_temp_dir(), 'fsz_zip_');
                if ($nestedPath !== false) {
                    file_put_contents($nestedPath, $entry);
                    $issues = [...$issues, ...$this->scanArchive($nestedPath, $depth + 1, $entryPath, $expandedBytes)];
                    @unlink($nestedPath);
                }
            }
        }

        $zip->close();
        return $issues;
    }

    private function isPathTraversal(string $name): bool
    {
        return str_contains($name, '../') || str_starts_with($name, '/') || preg_match('/^[a-z]:\//i', $name) === 1;
    }

    private function looksLikeZip(string $name, string $content, int|null $reportedSize): bool
    {
        if (str_ends_with($name, '.zip') || str_ends_with($name, '.docx') || str_ends_with($name, '.xlsx') || str_ends_with($name, '.pptx')) {
            return true;
        }

        if (($reportedSize ?? strlen($content)) < 4) {
            return false;
        }

        return str_starts_with($content, "PK\x03\x04") || str_starts_with($content, "PK\x05\x06") || str_starts_with($content, "PK\x07\x08");
    }
}
