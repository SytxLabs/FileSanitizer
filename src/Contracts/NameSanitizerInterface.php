<?php

namespace SytxLabs\FileSanitizer\Contracts;

interface NameSanitizerInterface
{
    public function sanitize(string $filename, string $replacement = '_'): string;
}
