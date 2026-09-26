<?php

namespace SytxLabs\FileSanitizer\Contracts;

use SytxLabs\FileSanitizer\Dto\SanitizeReport;

interface SanitizerInterface
{
    public function __construct(?StreamInterface $stream = null, ?OutputInterface $output = null, ?array $options = null);

    public function supports(string $mimeType, string $path): bool;

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport;
}
