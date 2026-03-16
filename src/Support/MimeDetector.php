<?php

namespace SytxLabs\FileSanitizer\Support;

use RuntimeException;

final class MimeDetector
{
    public function detect(string $path): string
    {
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        if ($finfo === false) {
            throw new RuntimeException('Unable to open fileinfo extension.');
        }

        $mimeType = finfo_file($finfo, $path);
        finfo_close($finfo);

        if ($mimeType === false || $mimeType === '') {
            throw new RuntimeException(sprintf('Unable to determine MIME type for "%s".', $path));
        }

        return strtolower(trim($mimeType));
    }
}
