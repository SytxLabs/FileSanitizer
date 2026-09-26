<?php

namespace SytxLabs\FileSanitizer\Scanner;

use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Stream\ChunkedIoTrait;

final class GenericPatternScanner implements ScannerInterface
{
    use ChunkedIoTrait;

    private const OVERLAP = 256;

    private const PATTERNS = [
        'xss_script_tag' => '/<\s*script\b/i',
        'xss_javascript_url' => '/javascript\s*:/i',
        'xss_data_html' => '/data\s*:\s*text\/html/i',
        'xss_inline_handler' => '/on(?:load|error|click|mouseover|focus|submit|pointerdown)\s*=/i',
        'xss_eval' => '/\beval\s*\(/i',
        'xss_function_ctor' => '/\b(?:new\s+function\s*\(|function\s*\(|new\s+Function\s*\()/i',
        'dom_sink' => '/(?:innerhtml|outerhtml|document\.write|insertadjacenthtml)\b/i',
        'cookie_access' => '/document\.cookie/i',
        'iframe_embed' => '/<\s*iframe\b/i',
        'php_exec' => '/\b(?:shell_exec|exec|system|passthru|proc_open|popen)\s*\(/i',
        'html_meta_refresh' => '/<meta[^>]+http-equiv\s*=\s*["\']?refresh/i',
        'html_base_tag' => '/<\s*base\b/i',
        'css_expression' => '/expression\s*\(/i',
        'css_import' => '/@import\b/i',
    ];

    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        return true;
    }

    public function scan(string $path, string $mimeType): ScanReport
    {
        $this->stream->rewind();
        $size = $this->stream->size();
        $found = $this->scanRangeForPatterns($this->stream, $size === false ? PHP_INT_MAX : $size, self::PATTERNS, overlap: self::OVERLAP);
        return $found === [] ? ScanReport::clean() : ScanReport::unsafe(array_map(static fn (string $code): Issue => new Issue($code, sprintf('Suspicious pattern detected: %s', $code), IssueSeverity::Error), $found));
    }
}
