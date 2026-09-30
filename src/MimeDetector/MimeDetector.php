<?php

namespace SytxLabs\FileSanitizer\MimeDetector;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\MimeDetectorInterface;

class MimeDetector implements MimeDetectorInterface
{
    public function detect(string $path): string
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        // @codeCoverageIgnoreStart
        if ($finfo === false) {
            throw new RuntimeException('Unable to open fileinfo extension.');
        }
        // @codeCoverageIgnoreEnd
        $mimeType = finfo_file($finfo, $path);
        if ($mimeType === false || $mimeType === '') {
            throw new RuntimeException(sprintf('Unable to determine MIME type for "%s".', $path));
        }
        return strtolower(trim($mimeType));
    }
}
