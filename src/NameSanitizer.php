<?php

namespace SytxLabs\FileSanitizer;

use SytxLabs\FileSanitizer\Contracts\NameSanitizerInterface;

final class NameSanitizer implements NameSanitizerInterface
{
    private const MAX_LENGTH = 255;
    private const RESERVED_WINDOWS_NAMES = ['CON', 'PRN', 'AUX', 'NUL', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'];

    public function sanitize(string $filename, string $replacement = '_'): string
    {
        $segments = explode('/', str_replace('\\', '/', $filename));
        $filename = preg_replace('/[^A-Za-z0-9._\-() ]/u', $replacement, (string) end($segments)) ?? '';
        $filename = str_replace('..', $replacement . $replacement, trim($filename, " .\t\n\r\0\x0B"));

        if ($filename === '') {
            $filename = 'file';
        }
        if (in_array(strtoupper(pathinfo($filename, PATHINFO_FILENAME)), self::RESERVED_WINDOWS_NAMES, true)) {
            $filename = $replacement . $filename;
        }
        if (strlen($filename) <= self::MAX_LENGTH) {
            return $filename;
        }
        $extension = pathinfo($filename, PATHINFO_EXTENSION);
        $suffix = $extension !== '' ? '.' . $extension : '';
        return substr(pathinfo($filename, PATHINFO_FILENAME), 0, max(1, self::MAX_LENGTH - strlen($suffix))) . $suffix;
    }
}
