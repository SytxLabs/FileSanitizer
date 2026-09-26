<?php

namespace SytxLabs\FileSanitizer\Contracts;

use SytxLabs\FileSanitizer\Dto\ScanReport;

interface ScannerInterface
{
    public function __construct(?StreamInterface $stream = null, ?array $options = null);

    public function supports(string $mimeType, string $path): bool;

    public function scan(string $path, string $mimeType): ScanReport;
}
