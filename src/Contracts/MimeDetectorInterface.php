<?php

namespace SytxLabs\FileSanitizer\Contracts;

interface MimeDetectorInterface
{
    public function detect(string $path): string;
}
