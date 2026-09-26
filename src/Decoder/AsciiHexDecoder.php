<?php

namespace SytxLabs\FileSanitizer\Decoder;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;

final class AsciiHexDecoder implements DecoderInterface
{
    public function supports(string $filter): bool
    {
        return in_array(strtoupper(trim($filter, "/ \t\r\n")), ['ASCIIHEXDECODE', 'AHX'], true);
    }

    public function decode(string $data): string
    {
        $end = strpos($data, '>');
        $hex = preg_replace('/[^0-9A-Fa-f]/', '', $end !== false ? substr($data, 0, $end) : $data) ?? '';
        if ($hex === '') {
            return $data;
        }
        if (strlen($hex) % 2 === 1) {
            $hex .= '0';
        }
        $decoded = @hex2bin($hex);
        return $decoded === false ? $data : $decoded;
    }
}
