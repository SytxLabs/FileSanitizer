<?php

namespace SytxLabs\FileSanitizer\Scanner;

use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Stream\ChunkedIoTrait;

final class SvgScanner implements ScannerInterface
{
    use ChunkedIoTrait;

    private const OVERLAP = 256;

    private const PATTERNS = [
        'svg_foreignobject' => '/<\s*foreignobject\b/i',
        'svg_animate' => '/<\s*animate\b/i',
        'svg_active_content' => '/<\s*(?:script|iframe|embed|object|foreignObject|animate|set)\b/i',
    ];

    private const MESSAGES = ['svg_active_content' => 'SVG contains active or externally-referential content elements.'];

    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        return str_starts_with($mimeType, 'image/svg') || str_ends_with(strtolower($path), '.svg');
    }

    public function scan(string $path, string $mimeType): ScanReport
    {
        $this->stream->rewind();
        $size = $this->stream->size();
        $found = $this->scanRangeForPatterns($this->stream, $size === false ? PHP_INT_MAX : $size, self::PATTERNS, overlap: self::OVERLAP);
        return $found === [] ? ScanReport::clean() : ScanReport::unsafe(array_map(static fn (string $code): Issue => new Issue($code, self::MESSAGES[$code] ?? sprintf('Suspicious pattern detected: %s', $code), IssueSeverity::Error), $found));
    }
}
