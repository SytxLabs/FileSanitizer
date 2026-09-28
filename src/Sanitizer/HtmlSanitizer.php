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

final class HtmlSanitizer implements SanitizerInterface
{
    private const ALLOWED_TAGS = ['html', 'head', 'body', 'title', 'meta', 'div', 'span', 'p', 'br', 'hr', 'strong', 'b', 'em', 'i', 'u', 'small', 'ul', 'ol', 'li', 'blockquote', 'pre', 'code', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td', 'a', 'img', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6'];
    private const GLOBAL_ATTRIBUTES = ['class', 'id', 'title', 'lang', 'dir', 'aria-label', 'aria-hidden', 'role'];
    private const URL_ATTRIBUTES = ['href', 'src'];
    private const VOID_ELEMENTS = ['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'];
    private const RAWTEXT_ELEMENTS = ['script', 'style'];
    private const TAG_NAME_STOP_CHARS = [' ', "\t", "\n", "\r", '/', '>'];
    private const ATTR_BOUNDARY_CHARS = ["\t", "\n", "\f", "\r", ' ', '>', '/'];

    /** @param array<string, mixed>|null $options */
    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, private readonly ?array $options = null)
    {
    }

    public function supports(string $mimeType, string $path): bool
    {
        return in_array($mimeType, ['text/html', 'application/xhtml+xml'], true);
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

        return new SanitizeReport($outputPath, $removed > 0, [new Issue('html_cleaned', sprintf('HTML cleaned with allowlist rules; %d risky nodes or attributes removed.', $removed), IssueSeverity::Info)]);
    }

    private function streamSanitize(StreamInterface $stream, OutputInterface $writer, int $bufferSize, int $maxCarry): int
    {
        $carry = '';
        $removed = 0;
        $stack = [];
        $rawTextTag = null;
        $eof = false;
        $textAccum = '';

        while (!$eof) {
            $chunk = $stream->read($bufferSize);
            if ($chunk === false || $chunk === '') {
                $eof = true;
                $chunk = '';
            }
            if (strlen($carry) > $maxCarry) {
                $writer->write($this->textOut($carry));
                $carry = '';
                $stack = [];
                $rawTextTag = null;
            }
            if (strlen($textAccum) > $maxCarry) {
                $holdBack = min(strlen($textAccum), 40);
                $writer->write($this->textOut(substr($textAccum, 0, strlen($textAccum) - $holdBack)));
                $textAccum = substr($textAccum, strlen($textAccum) - $holdBack);
            }

            $buffer = $carry . $chunk;
            $carry = '';
            $len = strlen($buffer);
            $pos = 0;

            while (true) {
                if ($rawTextTag !== null) {
                    $pos = $this->resumeRawText($buffer, $pos, $len, $eof, $rawTextTag, $textAccum, $writer, $carry);
                    if ($pos >= $len) {
                        break;
                    }
                }

                if ($pos >= $len) {
                    if ($eof) {
                        $this->flushText($textAccum, $writer);
                    }
                    break;
                }

                if ($buffer[$pos] !== '<') {
                    $ltPos = strpos($buffer, '<', $pos);
                    if ($ltPos === false) {
                        if ($eof) {
                            $textAccum .= substr($buffer, $pos);
                            $this->flushText($textAccum, $writer);
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
                        $this->flushText($textAccum, $writer);
                        break;
                    }
                    $carry = substr($buffer, $pos);
                    break;
                }
                $this->flushText($textAccum, $writer);
                $next = $buffer[$pos + 1];
                if ($next === '!') {
                    $advance = $this->consumeMarkupDeclaration($buffer, $pos, $len, $eof, $writer);
                    if ($advance === null) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    $pos = $advance;
                    continue;
                }

                if ($next === '/') {
                    $advance = $this->consumeEndTag($buffer, $pos, $len, $eof, $stack, $rawTextTag, $writer);
                    if ($advance === null) {
                        $carry = substr($buffer, $pos);
                        break;
                    }
                    $pos = $advance;
                    continue;
                }

                if (!(($next >= 'a' && $next <= 'z') || ($next >= 'A' && $next <= 'Z'))) {
                    $textAccum .= '<';
                    $pos++;
                    continue;
                }
                $advance = $this->consumeStartTag($buffer, $pos, $len, $eof, $stack, $rawTextTag, $removed, $writer);
                if ($advance === null) {
                    $carry = substr($buffer, $pos);
                    break;
                }
                $pos = $advance;
            }
        }

        return $removed;
    }

    private function resumeRawText(string $buffer, int $pos, int $len, bool $eof, string $rawTextTag, string &$textAccum, OutputInterface $writer, string &$carry): int
    {
        $needle = '</' . $rawTextTag;
        $needleLen = strlen($needle);
        $searchFrom = $pos;
        $foundAt = false;
        $ambiguousAt = null;

        while (($candidate = stripos($buffer, $needle, $searchFrom)) !== false) {
            $afterPos = $candidate + $needleLen;
            if ($afterPos >= $len) {
                $ambiguousAt = $candidate;
                break;
            }
            if (in_array($buffer[$afterPos], self::ATTR_BOUNDARY_CHARS, true)) {
                $foundAt = $candidate;
                break;
            }
            $searchFrom = $candidate + 1;
        }

        if ($foundAt !== false) {
            if ($foundAt > $pos) {
                $textAccum .= substr($buffer, $pos, $foundAt - $pos);
            }
            $this->flushText($textAccum, $writer);
            return $foundAt;
        }

        $holdFrom = $ambiguousAt ?? max($pos, $len - ($needleLen - 1));
        if ($holdFrom > $pos) {
            $textAccum .= substr($buffer, $pos, $holdFrom - $pos);
        }
        if (!$eof) {
            $carry = substr($buffer, $holdFrom);
            return $len;
        }
        $textAccum .= substr($buffer, $holdFrom);
        $this->flushText($textAccum, $writer);
        return $len;
    }

    private function flushText(string &$textAccum, OutputInterface $writer): void
    {
        if ($textAccum !== '') {
            $writer->write($this->textOut($textAccum));
            $textAccum = '';
        }
    }

    private function consumeMarkupDeclaration(string $buffer, int $pos, int $len, bool $eof, OutputInterface $writer): ?int
    {
        if (substr($buffer, $pos, 4) === '<!--') {
            $endIdx = strpos($buffer, '-->', $pos + 4);
            if ($endIdx === false) {
                if (!$eof) {
                    return null;
                }
                $writer->write('<!--' . substr($buffer, $pos + 4) . '-->');
                return $len;
            }
            $writer->write(substr($buffer, $pos, $endIdx + 3 - $pos));
            return $endIdx + 3;
        }
        if ($len < $pos + 4 && !$eof) {
            return null;
        }
        $gtIdx = strpos($buffer, '>', $pos + 2);
        if ($gtIdx === false) {
            if (!$eof) {
                return null;
            }
            return $len;
        }
        return $gtIdx + 1;
    }

    /**
     * @param list<array{name: string, written: bool}> $stack
     */
    private function consumeEndTag(string $buffer, int $pos, int $len, bool $eof, array &$stack, ?string &$rawTextTag, OutputInterface $writer): ?int
    {
        $nameEnd = $this->findTagNameEnd($buffer, $pos + 2, $len);
        if ($nameEnd === null) {
            return $eof ? $len : null;
        }
        $gtIdx = strpos($buffer, '>', $nameEnd);
        if ($gtIdx === false) {
            return $eof ? $len : null;
        }
        $tagName = strtolower(substr($buffer, $pos + 2, $nameEnd - ($pos + 2)));

        $foundIdx = null;
        for ($j = count($stack) - 1; $j >= 0; $j--) {
            if ($stack[$j]['name'] === $tagName) {
                $foundIdx = $j;
                break;
            }
        }
        if ($foundIdx !== null) {
            while (count($stack) > $foundIdx) {
                $entry = array_pop($stack);
                if ($entry['written']) {
                    $writer->write('</' . $entry['name'] . '>');
                }
            }
            if ($rawTextTag === $tagName) {
                $rawTextTag = null;
            }
        }
        return $gtIdx + 1;
    }

    /**
     * @param list<array{name: string, written: bool}> $stack
     */
    private function consumeStartTag(string $buffer, int $pos, int $len, bool $eof, array &$stack, ?string &$rawTextTag, int &$removed, OutputInterface $writer): ?int
    {
        $nameEnd = $this->findTagNameEnd($buffer, $pos + 1, $len);
        if ($nameEnd === null) {
            return $eof ? $len : null;
        }
        $tail = $this->scanTagTail($buffer, $nameEnd, $len);
        if ($tail === null) {
            return $eof ? $len : null;
        }
        [$rawAttrs, $endPos] = $tail;
        $tagName = strtolower(substr($buffer, $pos + 1, $nameEnd - ($pos + 1)));
        $isVoid = in_array($tagName, self::VOID_ELEMENTS, true);
        $allowed = in_array($tagName, self::ALLOWED_TAGS, true);

        $keptAttrs = [];
        if ($allowed) {
            foreach ($rawAttrs as [$rawName, $decodedValue]) {
                $lname = strtolower($rawName);
                if (str_starts_with($lname, 'on')) {
                    $removed++;
                    continue;
                }
                if ($lname === 'style') {
                    $clean = $this->sanitizeStyle($decodedValue);
                    if ($clean === null) {
                        $removed++;
                        continue;
                    }
                    $keptAttrs[] = [$lname, $clean];
                    continue;
                }
                if (in_array($lname, self::URL_ATTRIBUTES, true)) {
                    if (!$this->isSafeUrl($decodedValue, $tagName === 'img' && $lname === 'src')) {
                        $removed++;
                        continue;
                    }
                    $keptAttrs[] = [$lname, $decodedValue];
                    continue;
                }
                if (!(in_array($lname, self::GLOBAL_ATTRIBUTES, true) || match ($tagName) {
                    'a' => in_array($lname, ['href', 'target', 'rel'], true),
                    'img' => in_array($lname, ['src', 'alt', 'width', 'height'], true),
                    'td', 'th' => in_array($lname, ['colspan', 'rowspan', 'scope'], true),
                    'meta' => in_array($lname, ['charset', 'name', 'content'], true),
                    default => false
                })) {
                    $removed++;
                    continue;
                }
                $keptAttrs[] = [$lname, $decodedValue];
            }
        }

        $isMetaRefresh = false;
        if ($allowed && $tagName === 'meta') {
            foreach ($rawAttrs as [$an, $av]) {
                if (strtolower($an) === 'http-equiv' && strtolower(trim($av)) === 'refresh') {
                    $isMetaRefresh = true;
                    break;
                }
            }
        }

        if ($isMetaRefresh) {
            $removed++;
        } elseif ($allowed) {
            if ($tagName === 'a') {
                $hasHref = false;
                foreach ($keptAttrs as [$an]) {
                    if ($an === 'href') {
                        $hasHref = true;
                        break;
                    }
                }
                if ($hasHref) {
                    $filtered = [];
                    foreach ($keptAttrs as $attr) {
                        if ($attr[0] === 'rel') {
                            continue;
                        }
                        $filtered[] = $attr;
                    }
                    $filtered[] = ['rel', 'nofollow noopener noreferrer'];
                    $keptAttrs = $filtered;
                }
            }
            $out = '<' . $tagName;
            foreach ($keptAttrs as [$an, $av]) {
                $out .= ' ' . $an . '="' . htmlspecialchars($av, ENT_QUOTES | ENT_HTML5, 'UTF-8') . '"';
            }
            $out .= '>';
            $writer->write($out);
            if (!$isVoid) {
                $stack[] = ['name' => $tagName, 'written' => true];
            }
        } else {
            $removed++;
            if (!$isVoid) {
                $stack[] = ['name' => $tagName, 'written' => false];
                if (in_array($tagName, self::RAWTEXT_ELEMENTS, true)) {
                    $rawTextTag = $tagName;
                }
            }
        }

        return $endPos + 1;
    }

    private function findTagNameEnd(string $buffer, int $pos, int $len): ?int
    {
        $i = $pos;
        while ($i < $len && !in_array($buffer[$i], self::TAG_NAME_STOP_CHARS, true)) {
            $i++;
        }
        return $i >= $len ? null : $i;
    }

    /** @return array{0: list<array{0: string, 1: string}>, 1: int}|null [attrs, endPos] */
    private function scanTagTail(string $buffer, int $pos, int $len): ?array
    {
        $attrs = [];
        $i = $pos;
        while (true) {
            while ($i < $len && in_array($buffer[$i], [' ', "\t", "\n", "\r"], true)) {
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

            while ($i < $len && in_array($buffer[$i], [' ', "\t", "\n", "\r"], true)) {
                $i++;
            }
            if ($i >= $len) {
                return null;
            }

            $value = '';
            if ($buffer[$i] === '=') {
                $i++;
                while ($i < $len && in_array($buffer[$i], [' ', "\t", "\n", "\r"], true)) {
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
                    while ($i < $len && !in_array($buffer[$i], [' ', "\t", "\n", "\r", '>'], true)) {
                        $i++;
                    }
                    if ($i >= $len) {
                        return null;
                    }
                    $value = substr($buffer, $valStart, $i - $valStart);
                }
            }
            $attrs[] = [$name, html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8')];
        }
    }

    private function textOut(string $raw): string
    {
        return htmlspecialchars(html_entity_decode($raw, ENT_QUOTES | ENT_HTML5, 'UTF-8'), ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }

    private function isSafeUrl(string $value, bool $allowImageDataUri): bool
    {
        $value = trim(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if ($value === '' || str_starts_with($value, '#') || str_starts_with($value, '/') || ($allowImageDataUri && preg_match('#^data:image/(?:png|gif|jpeg|webp);base64,#i', $value) === 1)) {
            return true;
        }
        return (preg_match('#^(?:https?|mailto|tel):#i', $value) === 1) || !preg_match('#^(?:javascript|data|vbscript|file):#i', $value);
    }

    private function sanitizeStyle(string $style): ?string
    {
        $decoded = html_entity_decode($style, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if (preg_match('/(?:expression\s*\(|@import\b|url\s*\(|behavior\s*:|-moz-binding\s*:)/i', $decoded) === 1) {
            return null;
        }
        return trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $decoded) ?? $decoded);
    }
}
