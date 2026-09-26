<?php

namespace SytxLabs\FileSanitizer\Scanner;

use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\ScanReport;

final class CompositeScanner implements ScannerInterface
{
    private const DEFAULT_SCANNER_CLASSES = [GenericPatternScanner::class, SvgScanner::class, PdfScanner::class, ArchiveScanner::class];

    /** @var list<ScannerInterface> */
    private readonly array $scanners;

    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?array $options = null)
    {
        $entries = $options['scanners'] ?? self::DEFAULT_SCANNER_CLASSES;
        $this->scanners = array_map(fn (ScannerInterface|string $entry): ScannerInterface => is_string($entry) ? new $entry($this->stream) : $entry, $entries);
    }

    public function supports(string $mimeType, string $path): bool
    {
        return true;
    }

    public function scan(string $path, string $mimeType): ScanReport
    {
        $issues = [];
        foreach ($this->scanners as $scanner) {
            if (!$scanner->supports($mimeType, $path)) {
                continue;
            }
            $issues = [...$issues, ...$scanner->scan($path, $mimeType)->issues];
        }
        return $issues === [] ? ScanReport::clean() : ScanReport::unsafe($issues);
    }
}
