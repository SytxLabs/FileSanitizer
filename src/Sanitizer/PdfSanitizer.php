<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\DecoderInterface;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Decoder\Ascii85Decoder;
use SytxLabs\FileSanitizer\Decoder\AsciiHexDecoder;
use SytxLabs\FileSanitizer\Decoder\FlateDecoder;
use SytxLabs\FileSanitizer\Decoder\LzwDecoder;
use SytxLabs\FileSanitizer\Decoder\RunLengthDecoder;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\Stream\ChunkedIoTrait;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class PdfSanitizer implements SanitizerInterface
{
    use ChunkedIoTrait;

    private const RAW_ACTIVE_CONTENT_PATTERN = '/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/AA\b/i';
    private const DECODED_ACTIVE_CONTENT_PATTERN = '/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/AA\b|<\s*script\b|javascript\s*:/i';
    private const STREAM_KEYWORD_PATTERN = '/(?<![A-Za-z])stream[ \t\f\x00]*(\r\n|\r|\n)/';
    private const LOOKBEHIND = 4096;

    /** @var list<DecoderInterface> */
    private readonly array $decoders;

    private readonly int $streamBufferCap;

    /** @param array<string, mixed>|null $options */
    public function __construct(private readonly ?StreamInterface $stream = null, private readonly ?OutputInterface $output = null, ?array $options = null)
    {
        $options ??= [];
        $this->decoders = $options['decoders'] ?? [new FlateDecoder(), new AsciiHexDecoder(), new Ascii85Decoder(), new RunLengthDecoder(), new LzwDecoder()];
        $this->streamBufferCap = $options['streamBufferCap'] ?? 8388608;
    }

    public function supports(string $mimeType, string $path): bool
    {
        return $mimeType === 'application/pdf' || str_ends_with(strtolower($path), '.pdf');
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        if ($this->stream === null || $this->output === null) {
            throw new RuntimeException('PdfSanitizer requires a stream and output to be injected via the constructor.');
        }

        $size = $this->stream->size();
        if ($size === false) {
            throw new RuntimeException('Could not read PDF.');
        }

        $this->stream->rewind();
        $rawActiveContent = $this->scanRangeForPatterns($this->stream, $size, ['active' => self::RAW_ACTIVE_CONTENT_PATTERN]) !== [];
        $this->stream->rewind();
        $streamsDangerous = false;
        $this->walkStreams($this->stream, null, $streamsDangerous);
        $hadActiveContent = $rawActiveContent || $streamsDangerous;

        if ($hadActiveContent && !$sanitizeAlways) {
            throw new RuntimeException('PDF contains active content and was rejected. Call process($inputPath, $outputPath, true) to sanitize anyway.');
        }

        $issues = [];
        $changed = false;
        $tempFiles = [];
        $currentPath = $inputPath;

        if ($streamsDangerous) {
            $currentPath = $this->runStep($currentPath, function (StreamInterface $in, OutputInterface $out) use (&$changed) {
                $this->walkStreams($in, $out, $changed);
            }, $tempFiles);
            $issues[] = new Issue('pdf_stream_active_content_removed', 'PDF contained active content hidden inside a decoded stream (e.g. FlateDecode-compressed JavaScript); the affected stream was blanked.', IssueSeverity::Warning);
        }

        if ($hadActiveContent) {
            $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/\/OpenAction\s+(?:\d+\s+\d+\s+R|<<.*?>>|\[.*?\])/is', ['#\/OpenAction\b#i'], $changed);
            $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/\/AA\s*<<.*?>>/is', ['#\/AA\b#i'], $changed);
            $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/\/JavaScript\s+(?:\d+\s+\d+\s+R|\(.*?\)|<<.*?>>)/is', ['#\/JavaScript\b#i'], $changed);
            $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/\/JS\s+(?:\(.*?\)|<.*?>|\d+\s+\d+\s+R)/is', ['#\/JS\b#i'], $changed, '/JS ()');
            $issues[] = new Issue('pdf_active_content_removed', 'PDF contained active-content markers; best-effort cleanup removed common action and JavaScript references.', IssueSeverity::Warning);
        }

        $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/<\?xpacket.*?<\/x:xmpmeta>\s*<\?xpacket end="w"\?>/is', ['#<\?xpacket#i'], $changed);
        $currentPath = $this->applySubstitution($currentPath, $tempFiles, '/\/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)\s*\((?:\\.|[^()])*\)/i', ['#\/(?:Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)\b#i'], $changed, '/$1 ()');

        $finalSize = filesize($currentPath);
        // @codeCoverageIgnoreStart
        if ($finalSize === false) {
            $this->cleanupTempFiles($tempFiles);
            throw new RuntimeException('Could not write sanitized PDF.');
        }
        // @codeCoverageIgnoreEnd
        $finalIn = new FileChunker($currentPath);
        try {
            $this->copyRange($finalIn, $this->output, $finalSize);
        } finally {
            $finalIn->close();
        }
        $this->cleanupTempFiles($tempFiles);

        $issues[] = new Issue(
            'pdf_best_effort_cleanup',
            $hadActiveContent ? 'PDF was sanitized in best-effort mode; common active-content markers and metadata fields were removed or blanked.' : 'PDF metadata cleanup is best-effort only; common metadata fields were blanked.',
            IssueSeverity::Info
        );
        return new SanitizeReport($outputPath, $changed, $issues);
    }

    /** @param list<string> $tempFiles */
    private function runStep(string $currentPath, callable $step, array &$tempFiles): string
    {
        $target = tempnam(sys_get_temp_dir(), 'fsz_pdf_');
        // @codeCoverageIgnoreStart
        if ($target === false) {
            throw new RuntimeException('Could not create temporary file for PDF sanitization step.');
        }
        // @codeCoverageIgnoreEnd
        $in = new FileChunker($currentPath);
        $out = new FileWriter($target);
        try {
            $step($in, $out);
        } finally {
            $out->close();
            $in->close();
        }
        $tempFiles[] = $target;
        return $target;
    }

    /**
     * @param list<string> $tempFiles
     * @param list<string> $openMarkers
     */
    private function applySubstitution(string $currentPath, array &$tempFiles, string $pattern, array $openMarkers, bool &$changed, string $replacement = ''): string
    {
        return $this->runStep($currentPath, function (StreamInterface $in, OutputInterface $out) use ($pattern, $openMarkers, &$changed, $replacement) {
            $size = $in->size();
            $this->streamStripPatterns($in, $out, $size === false ? PHP_INT_MAX : $size, $pattern, $openMarkers, $changed, replacement: $replacement);
        }, $tempFiles);
    }

    /** @param list<string> $tempFiles */
    private function cleanupTempFiles(array $tempFiles): void
    {
        foreach ($tempFiles as $tempFile) {
            @unlink($tempFile);
        }
    }

    private function walkStreams(StreamInterface $in, ?OutputInterface $out, bool &$dangerFound): void
    {
        $carry = '';
        $inStreamBody = false;
        $filters = null;
        $body = '';
        $overflow = false;

        while (!$in->eof()) {
            $chunk = $in->read(1048576);
            if ($chunk === false || $chunk === '') {
                break;
            }
            $buffer = $carry . $chunk;
            $carry = '';
            $bufLen = strlen($buffer);
            $offset = 0;

            while (true) {
                if (!$inStreamBody) {
                    if (preg_match(self::STREAM_KEYWORD_PATTERN, $buffer, $m, PREG_OFFSET_CAPTURE, $offset) !== 1) {
                        break;
                    }
                    $kwPos = $m[0][1];
                    $matchEnd = $kwPos + strlen($m[0][0]);
                    if ($out !== null) {
                        $out->write(substr($buffer, $offset, $matchEnd - $offset));
                    }
                    $back = substr($buffer, max(0, $kwPos - self::LOOKBEHIND), min($kwPos, self::LOOKBEHIND));
                    $filters = $this->parseFilters($this->extractStreamDict($back));
                    $body = '';
                    $overflow = $filters === null;
                    $inStreamBody = true;
                    $offset = $matchEnd;
                    continue;
                }

                $endPos = strpos($buffer, 'endstream', $offset);
                if ($endPos !== false) {
                    $this->appendStreamBody($body, $overflow, $out, substr($buffer, $offset, $endPos - $offset));
                    $this->finishStreamBody($body, $overflow, $filters, $out, $dangerFound);
                    $inStreamBody = false;
                    $offset = $endPos + 9;
                    continue;
                }

                $tail = min($bufLen - $offset, 16);
                $this->appendStreamBody($body, $overflow, $out, substr($buffer, $offset, $bufLen - $offset - $tail));
                $carry = substr($buffer, $bufLen - $tail);
                $offset = $bufLen;
                break;
            }

            if (!$inStreamBody) {
                $start = max($offset, $bufLen - (self::LOOKBEHIND + 16));
                $out?->write(substr($buffer, $offset, $start - $offset));
                $carry = substr($buffer, $start);
            }
        }

        if ($inStreamBody) {
            $this->finishStreamBody($body, $overflow, $filters, $out, $dangerFound);
        } elseif ($carry !== '' && $out !== null) {
            $out->write($carry);
        }
    }

    private function appendStreamBody(string &$body, bool &$overflow, ?OutputInterface $out, string $piece): void
    {
        if ($piece === '') {
            return;
        }
        if ($overflow) {
            $out?->write($piece);
            return;
        }
        if (strlen($body) + strlen($piece) > $this->streamBufferCap) {
            $keep = $this->streamBufferCap - strlen($body);
            $body .= substr($piece, 0, $keep);
            if ($out !== null) {
                $out->write($body);
                $out->write(substr($piece, $keep));
            }
            $body = '';
            $overflow = true;
            return;
        }
        $body .= $piece;
    }

    /** @param list<string>|null $filters */
    private function finishStreamBody(string $body, bool $overflow, ?array $filters, ?OutputInterface $out, bool &$dangerFound): void
    {
        // A stream without a parseable /Filter is always flagged as overflow by the caller and was
        // already passed through while streaming, so there is nothing left to write here.
        if ($overflow || $filters === null) {
            return;
        }
        $decoder = $this->resolveDecoder($filters[0]);
        if ($decoder === null) {
            $out?->write($body);
            return;
        }

        $decoded = $decoder->decode($body);
        $isDangerous = $decoded !== $body && preg_match(self::DECODED_ACTIVE_CONTENT_PATTERN, $decoded) === 1;
        if ($isDangerous) {
            $dangerFound = true;
        }
        $out?->write($isDangerous ? str_repeat(' ', strlen($body)) : $body);
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

    /** @return list<string>|null */
    private function parseFilters(string $dict): ?array
    {
        return preg_match('/\/Filter\s*\/?\s*([A-Za-z0-9]+)/', $dict, $m) !== 1 ? null : [$m[1]];
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
}
