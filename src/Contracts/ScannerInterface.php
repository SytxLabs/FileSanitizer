<?php

namespace SytxLabs\FileSanitizer\Contracts;

use SytxLabs\FileSanitizer\Dto\ScanReport;

interface ScannerInterface
{
    public function scan(string $path, string $mimeType): ScanReport;
}
