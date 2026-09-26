<?php

namespace SytxLabs\FileSanitizer\Scanner;

use SytxLabs\FileSanitizer\Contracts\DecoderInterface;
use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Decoder\Ascii85Decoder;
use SytxLabs\FileSanitizer\Decoder\AsciiHexDecoder;
use SytxLabs\FileSanitizer\Decoder\FlateDecoder;
use SytxLabs\FileSanitizer\Decoder\LzwDecoder;
use SytxLabs\FileSanitizer\Decoder\RunLengthDecoder;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class PdfScanner implements ScannerInterface
{
    private const OVERLAP = 4096;

    private const DEFAULT_STREAM_BUFFER_CAP = 8388608;

    private const DEFAULT_DECODED_OUTPUT_CAP = 16777216;

    private const PDF_PATTERNS = [
        'pdf_javascript' => '/\/JavaScript\b/',
        'pdf_launch_action' => '/\/Launch\b/',
        'pdf_additional_actions' => '/\/AA\s*<</',
        'pdf_encrypted' => '/\/Encrypt\b/',
        'pdf_richmedia' => '/\/RichMedia/',
        'pdf_xfa' => '/\/XFA\s*[\[\d]/',
        'pdf_submit_form' => '/\/SubmitForm\b/',
        'pdf_goto_remote' => '/\/GoToR\b/',
    ];

    private const DECODED_MARKUP_PATTERNS = [
        'xss_script_tag' => '/<\s*script\b/i',
        'xss_javascript_url' => '/javascript\s*:/i',
        'xss_inline_handler' => '/on(?:load|error|click|mouseover|focus|submit|pointerdown)\s*=/i',
        'xss_eval' => '/\beval\s*\(/i',
        'dom_sink' => '/(?:innerhtml|outerhtml|document\.write|insertadjacenthtml)\b/i',
        'iframe_embed' => '/<\s*iframe\b/i',
    ];

    private const IMAGE_CODEC_FILTERS = ['DCTDecode', 'DCT', 'JPXDecode', 'CCITTFaxDecode', 'CCF', 'JBIG2Decode'];

    private const DANGEROUS_ATTACHMENT_SIGNATURES = [
        'MZ', "\x7fELF", "\xFE\xED\xFA\xCE", "\xFE\xED\xFA\xCF", "\xCE\xFA\xED\xFE", "\xCF\xFA\xED\xFE",
        "\xCA\xFE\xBA\xBE", "PK\x03\x04", "PK\x05\x06", "PK\x07\x08", "Rar!\x1A\x07", "7z\xBC\xAF\x27\x1C",
        "\x1F\x8B", "\xD0\xCF\x11\xE0", '#!',
    ];

    private const DEFAULT_BUFFER_SIZE = 1048576;

    /** @var list<DecoderInterface> */
    private readonly array $decoders;

    private readonly int $streamBufferCap;

    private readonly int $decodedOutputCap;

    private readonly int $bufferSize;

    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?array $options = null)
    {
        $options ??= [];
        $this->decoders = $options['decoders'] ?? [new FlateDecoder(), new AsciiHexDecoder(), new Ascii85Decoder(), new RunLengthDecoder(), new LzwDecoder()];
        $this->streamBufferCap = $options['streamBufferCap'] ?? self::DEFAULT_STREAM_BUFFER_CAP;
        $this->decodedOutputCap = $options['decodedOutputCap'] ?? self::DEFAULT_DECODED_OUTPUT_CAP;
        $this->bufferSize = $options['bufferSize'] ?? self::DEFAULT_BUFFER_SIZE;
    }

    public function supports(string $mimeType, string $path): bool
    {
        return $mimeType === 'application/pdf' || str_ends_with(strtolower($path), '.pdf');
    }

    public function scan(string $path, string $mimeType): ScanReport
    {
        $this->stream->rewind();

        $found = [];
        $rawTail = '';
        $state = $this->newStreamState();

        while (!$this->stream->eof()) {
            $chunk = $this->stream->read($this->bufferSize);
            if ($chunk === false || $chunk === '') {
                break;
            }

            $haystack = $rawTail . $chunk;
            $this->matchRaw($found, $haystack);
            $rawTail = substr($haystack, -self::OVERLAP);

            $this->feedStreamChunk($chunk, $state, $found);
        }

        if ($state['inStream']) {
            $this->finishStream($state, $found);
        }

        return $found === [] ? ScanReport::clean() : ScanReport::unsafe(array_values($found));
    }

    /** @return array<string, mixed> */
    private function newStreamState(): array
    {
        return ['carry' => '', 'inStream' => false, 'filters' => null, 'isObjStm' => false, 'isEmbedded' => false, 'isImage' => false, 'skip' => false, 'body' => '', 'overflow' => false];
    }

    /**
     * @param array<string, mixed> $state
     * @param array<string, Issue> $found
     */
    private function feedStreamChunk(string $chunk, array &$state, array &$found): void
    {
        $buffer = $state['carry'] . $chunk;
        $state['carry'] = '';
        $bufLen = strlen($buffer);
        $offset = 0;

        while (true) {
            if (!$state['inStream']) {
                if (preg_match('/(?<![A-Za-z])stream[ \t\f\x00]*(\r\n|\r|\n)/', $buffer, $m, PREG_OFFSET_CAPTURE, $offset) !== 1) {
                    break;
                }
                $kwPos = $m[0][1];
                $back = substr($buffer, max(0, $kwPos - self::OVERLAP), min($kwPos, self::OVERLAP));
                [$state['filters'], $state['isObjStm'], $state['isEmbedded'], $state['isImage']] = $this->parseStreamDict($this->extractStreamDict($back));
                $state['skip'] = $this->shouldSkipStream($state['filters'], $state['isObjStm'], $state['isEmbedded'], $state['isImage']);
                $state['body'] = '';
                $state['overflow'] = false;
                $state['inStream'] = true;
                $offset = $kwPos + strlen($m[0][0]);
                continue;
            }

            $endPos = strpos($buffer, 'endstream', $offset);
            if ($endPos !== false) {
                $this->appendBody($state, substr($buffer, $offset, $endPos - $offset));
                $this->finishStream($state, $found);
                $state['inStream'] = false;
                $offset = $endPos + 9;
                continue;
            }

            $tail = min($bufLen - $offset, 16);
            $this->appendBody($state, substr($buffer, $offset, $bufLen - $offset - $tail));
            $state['carry'] = substr($buffer, $bufLen - $tail);
            $offset = $bufLen;
            break;
        }

        if (!$state['inStream']) {
            $start = max($offset, $bufLen - (self::OVERLAP + 16));
            $state['carry'] = substr($buffer, $start);
        }
    }

    /** @param array<string, mixed> $state */
    private function appendBody(array &$state, string $piece): void
    {
        if ($state['skip'] || $state['overflow'] || $piece === '') {
            return;
        }
        if (strlen($state['body']) + strlen($piece) > $this->streamBufferCap) {
            $state['body'] .= substr($piece, 0, $this->streamBufferCap - strlen($state['body']));
            $state['overflow'] = true;
            return;
        }
        $state['body'] .= $piece;
    }

    private function finishStream(array &$state, array &$found): void
    {
        if ($state['skip']) {
            return;
        }

        $filters = $state['filters'];
        $isObjStm = $state['isObjStm'];
        $isEmbedded = $state['isEmbedded'];

        if ($filters === null) {
            if ($isEmbedded) {
                $this->inspectAttachment($state['body'], $found);
            }
            return;
        }

        if ($state['overflow']) {
            $this->flagUndecodable($isObjStm, $isEmbedded, $found);
            return;
        }

        $decoded = $this->decodeChain($state['body'], $filters);
        if ($decoded === null) {
            $this->flagUndecodable($isObjStm, $isEmbedded, $found);
            return;
        }

        $this->matchDecoded($found, $decoded);
        if ($isEmbedded) {
            $this->inspectAttachment($decoded, $found);
        }
    }

    private function decodeChain(string $body, array $filters): ?string
    {
        $data = $body;
        foreach ($filters as $filter) {
            $decoder = $this->resolveDecoder($filter);
            if ($decoder === null) {
                return null;
            }
            $decoded = $decoder->decode($data);
            if ($decoded === $data) {
                return null;
            }
            if (strlen($decoded) > $this->decodedOutputCap) {
                return null;
            }
            $data = $decoded;
        }

        return $data;
    }

    private function resolveDecoder(string $filter): ?DecoderInterface
    {
        foreach ($this->decoders as $decoder) {
            if ($decoder->supports($filter)) {
                return $decoder;
            }
        }
        return null;
    }

    private function shouldSkipStream(?array $filters, bool $isObjStm, bool $isEmbedded, bool $isImage): bool
    {
        if ($filters === null) {
            return !$isEmbedded;
        }
        foreach ($filters as $filter) {
            if (in_array($filter, self::IMAGE_CODEC_FILTERS, true)) {
                return true;
            }
        }
        return $isImage && !$isObjStm && !$isEmbedded;
    }

    /** @param array<string, Issue> $found */
    private function flagUndecodable(bool $isObjStm, bool $isEmbedded, array &$found): void
    {
        if ($isEmbedded) {
            $found['pdf_embedded_undecodable'] ??= new Issue('pdf_embedded_undecodable', 'An embedded file attachment uses an encoding that cannot be inspected and was rejected.', IssueSeverity::Error);
        } elseif ($isObjStm) {
            $found['pdf_objstm_undecodable'] ??= new Issue('pdf_objstm_undecodable', 'An object stream uses an encoding that cannot be inspected and was rejected.', IssueSeverity::Error);
        } else {
            $found['pdf_stream_undecodable'] ??= new Issue('pdf_stream_undecodable', 'A PDF stream uses an encoding that cannot be inspected and was rejected.', IssueSeverity::Error);
        }
    }

    /** @param array<string, Issue> $found */
    private function inspectAttachment(string $content, array &$found): void
    {
        if ($content === '') {
            return;
        }

        if (str_starts_with(ltrim(substr($content, 0, 16)), '%PDF-')) {
            $found['pdf_embedded_pdf'] ??= new Issue('pdf_embedded_pdf', 'An embedded file attachment is itself a PDF document and was rejected.', IssueSeverity::Error);
            return;
        }

        if (isset($found['pdf_embedded_executable'])) {
            return;
        }
        foreach (self::DANGEROUS_ATTACHMENT_SIGNATURES as $signature) {
            if (str_starts_with($content, $signature)) {
                $found['pdf_embedded_executable'] = new Issue('pdf_embedded_executable', 'An embedded file attachment is an executable or archive and was rejected.', IssueSeverity::Error);
                return;
            }
        }
    }

    private function extractStreamDict(string $back): string
    {
        $close = strrpos($back, '>>');
        if ($close === false) {
            return $back;
        }
        $depth = 1;
        $i = $close - 1;
        while ($i >= 1) {
            $pair = $back[$i - 1] . $back[$i];
            if ($pair === '>>') {
                $depth++;
                $i -= 2;
                continue;
            }
            if ($pair === '<<') {
                $depth--;
                if ($depth === 0) {
                    return substr($back, $i - 1, $close + 2 - ($i - 1));
                }
                $i -= 2;
                continue;
            }
            $i--;
        }

        return $back;
    }

    /** @return array{0: list<string>|null, 1: bool, 2: bool, 3: bool} */
    private function parseStreamDict(string $dict): array
    {
        $dict = $this->decodePdfNameHex(str_replace("\x00", ' ', preg_replace('/%[^\r\n]*/', ' ', $dict) ?? $dict));
        $isObjStm = preg_match('~/Type\s*/ObjStm\b~', $dict) === 1 || (preg_match('~/N\s+\d~', $dict) === 1 && preg_match('~/First\s+\d~', $dict) === 1);
        $isEmbedded = preg_match('~/Type\s*/EmbeddedFile\b~', $dict) === 1;
        $isImage = preg_match('~/Subtype\s*/Image\b~', $dict) === 1 && preg_match('~/Width\s+\d~', $dict) === 1 && preg_match('~/Height\s+\d~', $dict) === 1;

        $filters = null;
        if (preg_match_all('~/Filter\s*(\[[^\]]*\]|/[A-Za-z0-9]+|\d+\s+\d+\s+R)~', $dict, $mm) > 0) {
            $value = end($mm[1]);
            if ($value !== false && preg_match_all('~/([A-Za-z0-9]+)~', $value, $fm) && $fm[1] !== []) {
                $filters = $fm[1];
            } else {
                $filters = ['__unresolved__'];
            }
        } elseif (preg_match('~/Filter\b~', $dict) === 1) {
            $filters = ['__unresolved__'];
        }

        return [$filters, $isObjStm, $isEmbedded, $isImage];
    }

    /** @param array<string, Issue> $found */
    private function matchRaw(array &$found, string $text): void
    {
        $this->runPatterns($found, $text, self::PDF_PATTERNS);

        if (str_contains($text, '#')) {
            $decoded = $this->decodePdfNameHex($text);
            if ($decoded !== $text) {
                $this->runPatterns($found, $decoded, self::PDF_PATTERNS);
            }
        }
    }

    /** @param array<string, Issue> $found */
    private function matchDecoded(array &$found, string $text): void
    {
        $this->runPatterns($found, $text, self::PDF_PATTERNS);
        $this->runPatterns($found, $text, self::DECODED_MARKUP_PATTERNS);
    }

    /**
     * @param array<string, Issue>  $found
     * @param array<string, string> $patterns
     */
    private function runPatterns(array &$found, string $text, array $patterns): void
    {
        foreach ($patterns as $code => $pattern) {
            if (isset($found[$code])) {
                continue;
            }
            if (preg_match($pattern, $text) === 1) {
                $found[$code] = new Issue($code, sprintf('Suspicious pattern detected: %s', $code), IssueSeverity::Error);
            }
        }
    }

    private function decodePdfNameHex(string $text): string
    {
        return preg_replace_callback('/#([0-9A-Fa-f]{2})/', static fn (array $m): string => chr(hexdec($m[1])), $text) ?? $text;
    }
}
