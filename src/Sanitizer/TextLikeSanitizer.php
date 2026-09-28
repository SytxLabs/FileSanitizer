<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class TextLikeSanitizer implements SanitizerInterface
{
    /** @param array<string, mixed>|null $options */
    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, private readonly ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        return in_array($mimeType, ['text/plain', 'text/csv', 'application/json', 'application/xml', 'text/xml'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $options = $this->options ?? [];
        $stream = $this->stream ?? new FileChunker($inputPath);
        $output = $this->output ?? new FileWriter($outputPath);

        $bufferSize = $options['bufferSize'] ?? 1048576;
        $carry = '';
        $first = true;

        $stream->rewind();
        while (!$stream->eof()) {
            $chunk = $stream->read($bufferSize);
            if ($chunk === false || $chunk === '') {
                break;
            }
            [$safe, $carry] = $this->splitUtf8Safe($carry . $chunk);
            if ($first) {
                $safe = preg_replace('/^\xEF\xBB\xBF/', '', $safe) ?? $safe;
                $first = false;
            }
            $output->write($this->stripControlChars($safe));
        }
        if ($carry !== '') {
            $output->write($this->stripControlChars($carry));
        }
        return new SanitizeReport($outputPath, false, [new Issue('text_normalized', 'Text-like content normalized by removing BOM and control characters.', IssueSeverity::Info)]);
    }

    private function stripControlChars(string $text): string
    {
        return preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $text) ?? $text;
    }

    /** @return array{0: string, 1: string} */
    private function splitUtf8Safe(string $chunk): array
    {
        $len = strlen($chunk);
        if ($len === 0) {
            return ['', ''];
        }
        $i = $len;
        $continuationBytes = 0;
        while ($i > 0 && $continuationBytes < 3 && (ord($chunk[$i - 1]) & 0xC0) === 0x80) {
            $i--;
            $continuationBytes++;
        }
        if ($i > 0) {
            $leadByte = ord($chunk[$i - 1]);
            if (match (true) {
                ($leadByte & 0xE0) === 0xC0 => 2, ($leadByte & 0xF0) === 0xE0 => 3, ($leadByte & 0xF8) === 0xF0 => 4, default => 1
            } > $len - ($i - 1)) {
                $i--;
            }
        }
        return [substr($chunk, 0, $i), substr($chunk, $i)];
    }
}
