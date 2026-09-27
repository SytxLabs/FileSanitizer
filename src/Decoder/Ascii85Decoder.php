<?php

namespace SytxLabs\FileSanitizer\Decoder;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;

final class Ascii85Decoder implements DecoderInterface
{
    public function supports(string $filter): bool
    {
        return in_array(strtoupper(trim($filter, "/ \t\r\n")), ['ASCII85DECODE', 'A85'], true);
    }

    public function decode(string $data): string
    {
        $clean = preg_replace('/\s+/', '', $data) ?? $data;
        if (str_starts_with($clean, '<~')) {
            $clean = substr($clean, 2);
        }
        $end = strpos($clean, '~>');
        if ($end !== false) {
            $clean = substr($clean, 0, $end);
        }

        $out = '';
        $tuple = 0;
        $count = 0;
        for ($i = 0, $len = strlen($clean); $i < $len; $i++) {
            $char = $clean[$i];
            if ($char === 'z' && $count === 0) {
                $out .= "\0\0\0\0";
                continue;
            }
            $ord = ord($char);
            if ($ord < 33 || $ord > 117) {
                return $data;
            }
            $tuple = $tuple * 85 + ($ord - 33);
            if (++$count === 5) {
                $out .= chr(($tuple >> 24) & 0xFF) . chr(($tuple >> 16) & 0xFF) . chr(($tuple >> 8) & 0xFF) . chr($tuple & 0xFF);
                $tuple = 0;
                $count = 0;
            }
        }
        if ($count > 0) {
            for ($j = $count; $j < 5; $j++) {
                $tuple = $tuple * 85 + 84;
            }
            $bytes = chr(($tuple >> 24) & 0xFF) . chr(($tuple >> 16) & 0xFF) . chr(($tuple >> 8) & 0xFF) . chr($tuple & 0xFF);
            $out .= substr($bytes, 0, $count - 1);
        }

        return $out;
    }
}
