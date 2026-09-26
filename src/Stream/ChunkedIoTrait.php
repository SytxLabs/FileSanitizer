<?php

namespace SytxLabs\FileSanitizer\Stream;

use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;

trait ChunkedIoTrait
{
    private function copyRange(StreamInterface $in, OutputInterface $out, int $length, int $bufferSize = 1048576): void
    {
        while ($length > 0) {
            $piece = $in->read(min($bufferSize, $length));
            if ($piece === false || $piece === '') {
                break;
            }
            $out->write($piece);
            $length -= strlen($piece);
        }
    }

    private function readExact(StreamInterface $in, int $length): string
    {
        $data = '';
        while (strlen($data) < $length) {
            $piece = $in->read($length - strlen($data));
            if ($piece === false || $piece === '') {
                break;
            }
            $data .= $piece;
        }
        return $data;
    }

    /**
     * @param array<string, string> $patterns
     * @return list<string>
     */
    private function scanRangeForPatterns(StreamInterface $in, int $length, array $patterns, int $bufferSize = 1048576, int $overlap = 256): array
    {
        $found = [];
        $tail = '';
        $remaining = $length;

        while ($remaining > 0) {
            $piece = $in->read(min($bufferSize, $remaining));
            if ($piece === false || $piece === '') {
                break;
            }
            $remaining -= strlen($piece);

            $haystack = $tail . $piece;
            foreach ($patterns as $code => $pattern) {
                if (!in_array($code, $found, true) && preg_match($pattern, $haystack) === 1) {
                    $found[] = $code;
                }
            }
            $tail = substr($haystack, -$overlap);
        }

        return $found;
    }

    private function copyRangeWithPatternDetection(StreamInterface $in, OutputInterface $out, int $length, string $pattern, bool &$matchedAny, int $bufferSize = 1048576, int $overlap = 256): void
    {
        $tail = '';
        $remaining = $length;

        while ($remaining > 0) {
            $piece = $in->read(min($bufferSize, $remaining));
            if ($piece === false || $piece === '') {
                break;
            }
            $remaining -= strlen($piece);
            $out->write($piece);

            if (!$matchedAny) {
                $haystack = $tail . $piece;
                if (preg_match($pattern, $haystack) === 1) {
                    $matchedAny = true;
                }
                $tail = substr($haystack, -$overlap);
            }
        }
    }

    /** @param list<string> $openMarkerPatterns */
    private function streamStripPatterns(StreamInterface $in, OutputInterface $out, int $length, string $pattern, array $openMarkerPatterns, bool &$anyRemoved, int $bufferSize = 1048576, int $maxCarry = 4194304, string $replacement = ''): void
    {
        $carry = '';
        $remaining = $length;

        while ($remaining > 0) {
            $piece = $in->read(min($bufferSize, $remaining));
            if ($piece === false || $piece === '') {
                break;
            }
            $remaining -= strlen($piece);

            $window = $carry . $piece;
            $replaced = preg_replace($pattern, $replacement, $window);
            if ($replaced === null) {
                $replaced = $window;
            } elseif ($replaced !== $window) {
                $anyRemoved = true;
            }

            $boundary = strlen($replaced);
            foreach ($openMarkerPatterns as $openPattern) {
                if (preg_match($openPattern, $replaced, $m, PREG_OFFSET_CAPTURE) === 1) {
                    $boundary = min($boundary, $m[0][1]);
                }
            }
            if (strlen($replaced) - $boundary > $maxCarry) {
                $boundary = strlen($replaced) - $maxCarry;
            }

            $out->write(substr($replaced, 0, $boundary));
            $carry = substr($replaced, $boundary);
        }

        if ($carry !== '') {
            $final = preg_replace($pattern, $replacement, $carry);
            if ($final === null) {
                $final = $carry;
            } elseif ($final !== $carry) {
                $anyRemoved = true;
            }
            $out->write($final);
        }
    }
}
