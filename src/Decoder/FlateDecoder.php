<?php

namespace SytxLabs\FileSanitizer\Decoder;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;

final class FlateDecoder implements DecoderInterface
{
    public function supports(string $filter): bool
    {
        return in_array(strtoupper(trim($filter, "/ \t\r\n")), ['FLATEDECODE', 'FL'], true) && extension_loaded('zlib');
    }

    public function decode(string $data): string
    {
        // @codeCoverageIgnoreStart
        if (!extension_loaded('zlib')) {
            return $data;
        }
        // @codeCoverageIgnoreEnd
        $decoded = @gzuncompress($data);
        if ($decoded === false) {
            $decoded = @gzinflate($data);
        }
        if ($decoded === false && strlen($data) > 2) {
            $decoded = @gzinflate(substr($data, 2));
        }
        return $decoded === false ? $data : $decoded;
    }
}
