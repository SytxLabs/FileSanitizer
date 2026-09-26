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

final class SvgSanitizer implements SanitizerInterface
{
    private const DISALLOWED_ELEMENTS = [
        'script', 'foreignobject', 'iframe', 'object', 'embed', 'audio', 'video',
        'animate', 'animatemotion', 'animatetransform', 'set', 'discard',
        'metadata', 'desc', 'title', 'style', 'link', 'image', 'use',
    ];

    private const URL_ATTRIBUTES = ['href', 'xlink:href', 'src'];
    private const NAME_STOP_CHARS = [' ', "\t", "\n", "\r", '/', '>'];
    private const WHITESPACE_CHARS = [' ', "\t", "\n", "\r"];

    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, private readonly ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        return $mimeType === 'image/svg+xml' || str_ends_with(strtolower($path), '.svg');
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $options = $this->options ?? [];
        $stream = $this->stream ?? new FileChunker($inputPath);
        $writer = $this->output ?? new FileWriter($outputPath);

        $bufferSize = $options['bufferSize'] ?? 1048576;
        $maxCarry = $options['maxCarry'] ?? 4194304;

        $stream->rewind();
        $removed = $this->streamSanitize($stream, $writer, $bufferSize, $maxCarry);

        return new SanitizeReport($outputPath, $removed > 0, [new Issue('svg_cleaned', sprintf('SVG cleaned with strict policy rules; %d risky or metadata nodes/attributes removed.', $removed), IssueSeverity::Info)]);
    }

    private function streamSanitize(StreamInterface $stream, OutputInterface $writer, int $bufferSize, int $maxCarry): int
    {
        $carry = '';
        $removed = 0;
        $stack = [];
        $skipDepth = 0;
        $eof = false;
        $textAccum = '';

        $flushText = function () use (&$textAccum, &$stack, &$skipDepth, $writer) {
            if ($textAccum !== '') {
                if ($skipDepth === 0 && $stack !== []) {
                    $writer->write($this->xmlEncode($this->decodeValue($textAccum)));
                }
                $textAccum = '';
            }
        };

        while (!$eof) {
            $chunk = $stream->read($bufferSize);
            if ($chunk === false || $chunk === '') {
                $eof = true;
                $chunk = '';
            }
            if (strlen($carry) > $maxCarry) {
                if ($skipDepth === 0 && $stack !== []) {
                    $writer->write($this->xmlEncode($carry));
                }
                $carry = '';
                $stack = [];
                $skipDepth = 0;
            }
            if (strlen($textAccum) > $maxCarry) {
                $holdBack = min(strlen($textAccum), 40);
                if ($skipDepth === 0 && $stack !== []) {
                    $writer->write($this->xmlEncode($this->decodeValue(substr($textAccum, 0, strlen($textAccum) - $holdBack))));
                }
                $textAccum = substr($textAccum, strlen($textAccum) - $holdBack);
            }

            $buffer = $carry . $chunk;
            $carry = '';
            $len = strlen($buffer);
            $pos = 0;

            while (true) {
                if ($pos >= $len) {
                    if ($eof) {
                        $flushText();
                    }
                    break;
                }

                if ($buffer[$pos] !== '<') {
                    $ltPos = strpos($buffer, '<', $pos);
                    if ($ltPos === false) {
                        if ($eof) {
                            $textAccum .= substr($buffer, $pos);
                            $flushText();
                            break;
                        }
                        $safeEnd = max($pos, $len - 3);
                        if ($safeEnd > $pos) {
                            $textAccum .= substr($buffer, $pos, $safeEnd - $pos);
                        }
                        $carry = substr($buffer, $safeEnd);
                        break;
                    }
                    if ($ltPos > $pos) {
                        $textAccum .= substr($buffer, $pos, $ltPos - $pos);
                    }
                    $pos = $ltPos;
                }
                if ($pos + 1 >= $len) {
                    if ($eof) {
                        $textAccum .= '<';
                        $flushText();
                        break;
                    }
                    $carry = substr($buffer, $pos);
                    break;
                }
                $flushText();
                $next = $buffer[$pos + 1];

                if ($next === '!') {
                    if ($len - $pos < 9 && !$eof) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    if (substr($buffer, $pos, 4) === '<!--') {
                        $advance = $this->consumeComment($buffer, $pos, $len, $eof, $skipDepth, $stack, $writer);
                    } elseif (substr($buffer, $pos, 9) === '<![CDATA[') {
                        $advance = $this->consumeCdata($buffer, $pos, $len, $eof, $skipDepth, $stack, $writer);
                    } else {
                        $advance = $this->consumeDeclaration($buffer, $pos, $len, $eof);
                    }
                    if ($advance === null) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    $pos = $advance;
                    continue;
                }

                if ($next === '?') {
                    $advance = $this->consumePi($buffer, $pos, $len, $eof);
                    if ($advance === null) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    $pos = $advance;
                    continue;
                }

                if ($next === '/') {
                    $advance = $this->consumeEndTag($buffer, $pos, $len, $eof, $stack, $skipDepth, $writer);
                    if ($advance === null) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    $pos = $advance;
                    continue;
                }

                if (!(($next >= 'a' && $next <= 'z') || ($next >= 'A' && $next <= 'Z') || $next === '_' || $next === ':')) {
                    $textAccum .= '<';
                    $pos++;
                    continue;
                }

                $advance = $this->consumeStartTag($buffer, $pos, $len, $eof, $stack, $skipDepth, $removed, $writer);
                if ($advance === null) {
                    $carry = substr($buffer, $pos);
                    break;
                }
                $pos = $advance;
            }
        }

        return $removed;
    }

    private function consumeComment(string $buffer, int $pos, int $len, bool $eof, int $skipDepth, array $stack, OutputInterface $writer): ?int
    {
        $endIdx = strpos($buffer, '-->', $pos + 4);
        if ($endIdx === false) {
            if (!$eof) {
                return null;
            }
            if ($skipDepth === 0 && $stack !== []) {
                $writer->write('<!--' . substr($buffer, $pos + 4) . '-->');
            }
            return $len;
        }
        if ($skipDepth === 0 && $stack !== []) {
            $writer->write(substr($buffer, $pos, $endIdx + 3 - $pos));
        }
        return $endIdx + 3;
    }

    private function consumeCdata(string $buffer, int $pos, int $len, bool $eof, int $skipDepth, array $stack, OutputInterface $writer): ?int
    {
        $endIdx = strpos($buffer, ']]>', $pos + 9);
        if ($endIdx === false) {
            if (!$eof) {
                return null;
            }
            if ($skipDepth === 0 && $stack !== []) {
                $writer->write('<![CDATA[' . substr($buffer, $pos + 9) . ']]>');
            }
            return $len;
        }
        if ($skipDepth === 0 && $stack !== []) {
            $writer->write(substr($buffer, $pos, $endIdx + 3 - $pos));
        }
        return $endIdx + 3;
    }

    private function consumeDeclaration(string $buffer, int $pos, int $len, bool $eof): ?int
    {
        $i = $pos + 2;
        $depth = 0;
        $quote = null;
        while ($i < $len) {
            $ch = $buffer[$i];
            if ($quote !== null) {
                if ($ch === $quote) {
                    $quote = null;
                }
                $i++;
                continue;
            }
            if ($ch === '"' || $ch === "'") {
                $quote = $ch;
                $i++;
                continue;
            }
            if ($ch === '[') {
                $depth++;
                $i++;
                continue;
            }
            if ($ch === ']') {
                if ($depth > 0) {
                    $depth--;
                }
                $i++;
                continue;
            }
            if ($ch === '>' && $depth === 0) {
                return $i + 1;
            }
            $i++;
        }
        return $eof ? $len : null;
    }

    private function consumePi(string $buffer, int $pos, int $len, bool $eof): ?int
    {
        $endIdx = strpos($buffer, '?>', $pos + 2);
        if ($endIdx === false) {
            return $eof ? $len : null;
        }
        return $endIdx + 2;
    }

    private function consumeEndTag(string $buffer, int $pos, int $len, bool $eof, array &$stack, int &$skipDepth, OutputInterface $writer): ?int
    {
        $gtIdx = strpos($buffer, '>', $pos + 2);
        if ($gtIdx === false) {
            return $eof ? $len : null;
        }
        if ($skipDepth > 0) {
            $skipDepth--;
            return $gtIdx + 1;
        }
        if ($stack !== []) {
            $name = array_pop($stack);
            $writer->write('</' . $name . '>');
        }
        return $gtIdx + 1;
    }

    private function consumeStartTag(string $buffer, int $pos, int $len, bool $eof, array &$stack, int &$skipDepth, int &$removed, OutputInterface $writer): ?int
    {
        $nameEnd = $this->findTagNameEnd($buffer, $pos + 1, $len);
        if ($nameEnd === null) {
            return $eof ? $len : null;
        }
        $tail = $this->scanTagTail($buffer, $nameEnd, $len);
        if ($tail === null) {
            return $eof ? $len : null;
        }
        [$rawAttrs, $gtIdx] = $tail;
        $tagName = substr($buffer, $pos + 1, $nameEnd - ($pos + 1));
        $selfClosing = $buffer[$gtIdx - 1] === '/';
        $endPos = $gtIdx + 1;

        if ($skipDepth > 0) {
            if (!$selfClosing) {
                $skipDepth++;
            }
            return $endPos;
        }

        $colonPos = strrpos($tagName, ':');
        if (in_array(strtolower($colonPos === false ? $tagName : substr($tagName, $colonPos + 1)), self::DISALLOWED_ELEMENTS, true)) {
            $removed++;
            if (!$selfClosing) {
                $skipDepth = 1;
            }
            return $endPos;
        }

        $keptAttrs = [];
        foreach ($rawAttrs as [$rawName, $rawValue]) {
            $lname = strtolower($rawName);
            $decoded = $this->decodeValue($rawValue);
            $checkValue = trim($decoded);

            if (str_starts_with($lname, 'on')) {
                $removed++;
                continue;
            }
            if (in_array($lname, self::URL_ATTRIBUTES, true) && !($checkValue === '' || str_starts_with($checkValue, '#') || (preg_match('#^(?:https?|data|javascript|vbscript|file):#i', $checkValue) !== 1))) {
                $removed++;
                continue;
            }
            if ($lname === 'style' && preg_match('/(?:expression\s*\(|@import\b|url\s*\(|behavior\s*:|-moz-binding\s*:)/i', $checkValue) === 1) {
                $removed++;
                continue;
            }
            $keptAttrs[] = [$rawName, $decoded];
        }

        $out = '<' . $tagName;
        foreach ($keptAttrs as [$an, $av]) {
            $out .= ' ' . $an . '="' . $this->xmlEncode($av) . '"';
        }
        $out .= $selfClosing ? '/>' : '>';
        $writer->write($out);
        if (!$selfClosing) {
            $stack[] = $tagName;
        }

        return $endPos;
    }

    private function findTagNameEnd(string $buffer, int $pos, int $len): ?int
    {
        $i = $pos;
        while ($i < $len && !in_array($buffer[$i], self::NAME_STOP_CHARS, true)) {
            $i++;
        }
        return $i >= $len ? null : $i;
    }

    /** @return array{0: list<array{0: string, 1: string}>, 1: int}|null [attrs, gtIndex] */
    private function scanTagTail(string $buffer, int $pos, int $len): ?array
    {
        $attrs = [];
        $i = $pos;
        while (true) {
            while ($i < $len && in_array($buffer[$i], self::WHITESPACE_CHARS, true)) {
                $i++;
            }
            if ($i >= $len) {
                return null;
            }
            if ($buffer[$i] === '>') {
                return [$attrs, $i];
            }
            if ($buffer[$i] === '/') {
                if ($i + 1 >= $len) {
                    return null;
                }
                if ($buffer[$i + 1] === '>') {
                    return [$attrs, $i + 1];
                }
                $i++;
                continue;
            }

            $nameStart = $i;
            while ($i < $len && !in_array($buffer[$i], [' ', "\t", "\n", "\r", '=', '/', '>'], true)) {
                $i++;
            }
            if ($i >= $len) {
                return null;
            }
            $name = substr($buffer, $nameStart, $i - $nameStart);

            while ($i < $len && in_array($buffer[$i], self::WHITESPACE_CHARS, true)) {
                $i++;
            }
            if ($i >= $len) {
                return null;
            }

            $value = '';
            if ($buffer[$i] === '=') {
                $i++;
                while ($i < $len && in_array($buffer[$i], self::WHITESPACE_CHARS, true)) {
                    $i++;
                }
                if ($i >= $len) {
                    return null;
                }
                $quote = $buffer[$i];
                if ($quote === '"' || $quote === "'") {
                    $i++;
                    $closeIdx = strpos($buffer, $quote, $i);
                    if ($closeIdx === false) {
                        return null;
                    }
                    $value = substr($buffer, $i, $closeIdx - $i);
                    $i = $closeIdx + 1;
                } else {
                    $valStart = $i;
                    while ($i < $len && !in_array($buffer[$i], [' ', "\t", "\n", "\r", '>', '/'], true)) {
                        $i++;
                    }
                    if ($i >= $len) {
                        return null;
                    }
                    $value = substr($buffer, $valStart, $i - $valStart);
                }
            }
            $attrs[] = [$name, $value];
        }
    }

    private function decodeValue(string $raw): string
    {
        return html_entity_decode($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    private function xmlEncode(string $decoded): string
    {
        return htmlspecialchars($decoded, ENT_QUOTES | ENT_XML1, 'UTF-8');
    }
}
