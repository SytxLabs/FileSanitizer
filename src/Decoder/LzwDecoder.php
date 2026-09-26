<?php

namespace SytxLabs\FileSanitizer\Decoder;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;

final class LzwDecoder implements DecoderInterface
{
    public function supports(string $filter): bool
    {
        return in_array(strtoupper(trim($filter, "/ \t\r\n")), ['LZWDECODE', 'LZW'], true);
    }

    public function decode(string $data): string
    {
        $table = [];
        for ($i = 0; $i < 256; $i++) {
            $table[$i] = chr($i);
        }
        $nextCode = 258;
        $codeLen = 9;
        $prev = -1;

        $out = '';
        $bitBuffer = 0;
        $bitCount = 0;
        for ($i = 0, $len = strlen($data); $i < $len; $i++) {
            $bitBuffer = ($bitBuffer << 8) | ord($data[$i]);
            $bitCount += 8;
            while ($bitCount >= $codeLen) {
                $bitCount -= $codeLen;
                $code = ($bitBuffer >> $bitCount) & ((1 << $codeLen) - 1);

                if ($code === 256) {
                    $table = array_slice($table, 0, 256, true);
                    $nextCode = 258;
                    $codeLen = 9;
                    $prev = -1;
                    continue;
                }
                if ($code === 257) {
                    return $out === '' ? $data : $out;
                }

                if ($prev === -1) {
                    if (!isset($table[$code])) {
                        return $data;
                    }
                    $entry = $table[$code];
                } elseif (isset($table[$code])) {
                    $entry = $table[$code];
                    $table[$nextCode++] = $table[$prev] . $entry[0];
                } elseif ($code === $nextCode) {
                    $entry = $table[$prev] . $table[$prev][0];
                    $table[$nextCode++] = $entry;
                } else {
                    return $data;
                }

                $out .= $entry;
                $prev = $code;

                if ($nextCode + 1 >= (1 << $codeLen) && $codeLen < 12) {
                    $codeLen++;
                }
            }
        }

        return $out === '' ? $data : $out;
    }
}
