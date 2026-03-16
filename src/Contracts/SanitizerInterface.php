<?php

namespace SytxLabs\FileSanitizer\Contracts;

use SytxLabs\FileSanitizer\Dto\SanitizeReport;

interface SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool;

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport;
}
