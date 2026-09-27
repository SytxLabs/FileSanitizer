<?php

namespace SytxLabs\FileSanitizer\Decoder;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;

final class RunLengthDecoder implements DecoderInterface
{
    public function supports(string $filter): bool
    {
        return in_array(strtoupper(trim($filter, "/ \t\r\n")), ['RUNLENGTHDECODE', 'RL'], true);
    }

    public function decode(string $data): string
    {
        $out = '';
        for ($i = 0, $len = strlen($data); $i < $len;) {
            $n = ord($data[$i++]);
            if ($n === 128) {
                break;
            }
            if ($n < 128) {
                $out .= substr($data, $i, $n + 1);
                $i += $n + 1;
            } else {
                if ($i >= $len) {
                    break;
                }
                $out .= str_repeat($data[$i++], 257 - $n);
            }
        }
        return $out === '' ? $data : $out;
    }
}
