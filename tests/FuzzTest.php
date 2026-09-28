<?php

namespace SytxLabs\FileSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\Ascii85Decoder;
use SytxLabs\FileSanitizer\Decoder\AsciiHexDecoder;
use SytxLabs\FileSanitizer\Decoder\FlateDecoder;
use SytxLabs\FileSanitizer\Decoder\LzwDecoder;
use SytxLabs\FileSanitizer\Decoder\RunLengthDecoder;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\HtmlSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\SvgSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\VideoSanitizer;
use SytxLabs\FileSanitizer\Scanner\ArchiveScanner;
use SytxLabs\FileSanitizer\Scanner\GenericPatternScanner;
use SytxLabs\FileSanitizer\Scanner\PdfScanner;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;
use Throwable;

/**
 * This project's own scanners/sanitizers are hand-rolled byte-level parsers (no DOM, no ext-xml)
 * built specifically to survive hostile, malformed, or adversarially-truncated input without
 * crashing or hanging — that is the whole point of a bounded-buffer tokenizer. A fuzz test is the
 * right tool to gain confidence in that property directly, rather than only checking a fixed list
 * of hand-picked malformed inputs.
 *
 * Two techniques are used, matched to what each target needs:
 *  - pure random bytes for the byte-oriented decoders, where "garbage in" is the normal case they
 *    must already tolerate (an untrusted PDF stream is not obligated to be valid);
 *  - mutation of a small known-good fixture (flip/delete/insert bytes) for the structured tokenizers
 *    and container walkers (SVG/HTML/PDF/WAV/AVI/MP4), because purely random bytes essentially never
 *    resemble their container format closely enough to exercise the interesting near-valid branches
 *    (a truncated tag, a corrupted chunk length, an unterminated comment).
 *
 * The seed is fixed by default so a CI failure is reproducible; override it with FSZ_FUZZ_SEED to
 * explore a different corner of the input space (e.g. when hardening this test further).
 */
final class FuzzTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $seed = (int) (getenv('FSZ_FUZZ_SEED') ?: 1337);
        mt_srand($seed);

        $this->tempDir = sys_get_temp_dir() . '/fsz_fuzz_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    /** @return list<array{0: string}> */
    public static function decoderProvider(): array
    {
        return [
            'Ascii85Decoder' => [Ascii85Decoder::class],
            'AsciiHexDecoder' => [AsciiHexDecoder::class],
            'FlateDecoder' => [FlateDecoder::class],
            'RunLengthDecoder' => [RunLengthDecoder::class],
            'LzwDecoder' => [LzwDecoder::class],
        ];
    }

    /**
     * @dataProvider decoderProvider
     * decode() must never throw and must always return a string, no matter how malformed the
     * input is: it sits directly on untrusted, attacker-controlled PDF stream bytes.
     */
    public function testDecoderNeverThrowsOnRandomBytes(string $decoderClass): void
    {
        $decoder = new $decoderClass();

        for ($i = 0; $i < 300; $i++) {
            $input = random_bytes($this->randomInt(0, 512));
            try {
                $result = $decoder->decode($input);
            } catch (Throwable $e) {
                self::fail(sprintf('%s::decode() threw %s on iteration %d for input %s: %s', $decoderClass, get_class($e), $i, bin2hex($input), $e->getMessage()));
            }
            self::assertIsString($result);
        }
    }

    /**
     * SvgSanitizer's tokenizer must survive arbitrary mutations of a well-formed document without
     * throwing, hanging, or losing the DI-injected stream/writer contract, regardless of the chunk
     * boundaries the random bufferSize/maxCarry options force it to observe.
     */
    public function testSvgSanitizerSurvivesMutatedInputAcrossRandomChunkBoundaries(): void
    {
        $seed = '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script>'
            . '<metadata>x</metadata><a href="javascript:alert(1)">x</a>'
            . '<rect onclick="x()" style="background:url(javascript:1)" width="10" height="10"/>'
            . '<!-- comment --><![CDATA[data]]></svg>';

        for ($i = 0; $i < 60; $i++) {
            $mutated = $this->mutate($seed, $this->randomInt(1, 12));
            $input = $this->tempDir . '/fuzz.svg';
            $output = $this->tempDir . '/fuzz.out.svg';
            file_put_contents($input, $mutated);

            $options = ['bufferSize' => $this->randomInt(1, 64), 'maxCarry' => $this->randomInt(8, 256)];
            try {
                (new SvgSanitizer(new FileChunker($input), new FileWriter($output), $options))->sanitize($input, $output);
            } catch (Throwable $e) {
                self::fail(sprintf('SvgSanitizer threw %s on iteration %d (options=%s) for input %s: %s', get_class($e), $i, json_encode($options), bin2hex($mutated), $e->getMessage()));
            }
            self::assertFileExists($output);
            @unlink($input);
            @unlink($output);
        }
    }

    /**
     * HtmlSanitizer's tokenizer (RAWTEXT handling, same-name unwrap stack, entity decode/re-escape)
     * must likewise survive arbitrary mutation without throwing or hanging.
     */
    public function testHtmlSanitizerSurvivesMutatedInputAcrossRandomChunkBoundaries(): void
    {
        $seed = '<div onclick="x()">before<script>if (a<b) { var s = "</style><img src=x onerror=alert(1)>"; }</script>'
            . '<a href="javascript:alert(1)" rel="evil">bad</a><!-- c --><font color=red>outer<font color=blue>inner</font></font>ok</div>';

        for ($i = 0; $i < 60; $i++) {
            $mutated = $this->mutate($seed, $this->randomInt(1, 12));
            $input = $this->tempDir . '/fuzz.html';
            $output = $this->tempDir . '/fuzz.out.html';
            file_put_contents($input, $mutated);

            $options = ['bufferSize' => $this->randomInt(1, 64), 'maxCarry' => $this->randomInt(8, 256)];
            try {
                (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), $options))->sanitize($input, $output);
            } catch (Throwable $e) {
                self::fail(sprintf('HtmlSanitizer threw %s on iteration %d (options=%s) for input %s: %s', get_class($e), $i, json_encode($options), bin2hex($mutated), $e->getMessage()));
            }
            self::assertFileExists($output);
            @unlink($input);
            @unlink($output);
        }
    }

    /**
     * GenericPatternScanner runs on every file type; it must tolerate arbitrary bytes.
     */
    public function testGenericPatternScannerSurvivesRandomBytes(): void
    {
        for ($i = 0; $i < 60; $i++) {
            $input = $this->tempDir . '/fuzz.bin';
            file_put_contents($input, random_bytes($this->randomInt(0, 2048)));

            try {
                $report = (new GenericPatternScanner(new FileChunker($input)))->scan($input, 'application/octet-stream');
            } catch (Throwable $e) {
                self::fail(sprintf('GenericPatternScanner threw %s on iteration %d: %s', get_class($e), $i, $e->getMessage()));
            }
            self::assertIsBool($report->safe);
            @unlink($input);
        }
    }

    /**
     * PdfScanner's raw/decoded pattern matching and stream-dictionary parsing must survive both
     * pure random bytes and mutations of a structurally valid PDF with an embedded compressed
     * stream, across randomized internal buffer sizes.
     */
    public function testPdfScannerSurvivesRandomAndMutatedBytes(): void
    {
        $compressed = gzcompress('/JavaScript trigger; <script>alert(1)</script>');
        $seed = "%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >> endobj\n"
            . "2 0 obj\n<< /Filter /FlateDecode /Length " . strlen($compressed) . " >>\nstream\n"
            . $compressed . "\nendstream\nendobj\n%%EOF";

        for ($i = 0; $i < 50; $i++) {
            $useMutation = $this->randomInt(0, 1) === 1;
            $content = $useMutation ? $this->mutate($seed, $this->randomInt(1, 15)) : random_bytes($this->randomInt(0, 1024));

            $input = $this->tempDir . '/fuzz.pdf';
            file_put_contents($input, $content);

            try {
                $report = (new PdfScanner(new FileChunker($input), ['bufferSize' => $this->randomInt(8, 256)]))->scan($input, 'application/pdf');
            } catch (Throwable $e) {
                self::fail(sprintf('PdfScanner threw %s on iteration %d (mutation=%s) for input %s: %s', get_class($e), $i, $useMutation ? 'yes' : 'no', bin2hex($content), $e->getMessage()));
            }
            self::assertIsBool($report->safe);
            @unlink($input);
        }
    }

    /**
     * AudioSanitizer's MP3/WAV chunk walkers are hand-rolled binary parsers; mutating a structurally
     * valid WAV (declared chunk sizes, RIFF header) is far more likely to hit the interesting
     * malformed-length/truncation branches than pure random bytes would be.
     */
    public function testAudioSanitizerSurvivesMutatedWavBytes(): void
    {
        $fmtChunk = 'fmt ' . pack('V', 16) . str_repeat("\x00", 16);
        $listData = 'INFO' . 'IART' . pack('V', 4) . 'Bob0';
        $listChunk = 'LIST' . pack('V', strlen($listData)) . $listData;
        $dataChunk = 'data' . pack('V', 8) . str_repeat("\x7F", 8);
        $body = $fmtChunk . $listChunk . $dataChunk;
        $seed = 'RIFF' . pack('V', 4 + strlen($body)) . 'WAVE' . $body;

        for ($i = 0; $i < 50; $i++) {
            $mutated = $this->mutate($seed, $this->randomInt(1, 10));
            $input = $this->tempDir . '/fuzz.wav';
            $output = $this->tempDir . '/fuzz.out.wav';
            file_put_contents($input, $mutated);

            try {
                (new AudioSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
            } catch (Throwable $e) {
                self::fail(sprintf('AudioSanitizer threw %s on iteration %d for input %s: %s', get_class($e), $i, bin2hex($mutated), $e->getMessage()));
            }
            self::assertFileExists($output);
            @unlink($input);
            @unlink($output);
        }
    }

    /**
     * VideoSanitizer's MP4 atom walker and AVI chunk walker are likewise hand-rolled; mutate a
     * structurally valid MP4 (declared atom sizes) to reach the malformed-atom-size guard reliably.
     */
    public function testVideoSanitizerSurvivesMutatedMp4Bytes(): void
    {
        $ftyp = pack('N', 16) . 'ftyp' . 'isomavc1';
        $udta = pack('N', 16) . 'udta' . 'DEADBEEF';
        $mdat = pack('N', 8 + 7) . 'mdat' . 'ok-data';
        $seed = $ftyp . $udta . $mdat;

        for ($i = 0; $i < 50; $i++) {
            $mutated = $this->mutate($seed, $this->randomInt(1, 10));
            $input = $this->tempDir . '/fuzz.mp4';
            $output = $this->tempDir . '/fuzz.out.mp4';
            file_put_contents($input, $mutated);

            try {
                (new VideoSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output, true);
            } catch (Throwable $e) {
                self::fail(sprintf('VideoSanitizer threw %s on iteration %d for input %s: %s', get_class($e), $i, bin2hex($mutated), $e->getMessage()));
            }
            self::assertFileExists($output);
            @unlink($input);
            @unlink($output);
        }
    }

    /**
     * ArchiveScanner must tolerate a file that merely claims to be a ZIP (via extension/mimetype)
     * but is actually random bytes, without throwing — this is the open_failed path under fuzzing.
     */
    public function testArchiveScannerSurvivesRandomBytesClaimingToBeAZip(): void
    {
        for ($i = 0; $i < 30; $i++) {
            $input = $this->tempDir . '/fuzz.zip';
            file_put_contents($input, random_bytes($this->randomInt(0, 512)));

            try {
                $report = (new ArchiveScanner(new FileChunker($input)))->scan($input, 'application/zip');
            } catch (Throwable $e) {
                self::fail(sprintf('ArchiveScanner threw %s on iteration %d: %s', get_class($e), $i, $e->getMessage()));
            }
            self::assertIsBool($report->safe);
            @unlink($input);
        }
    }

    private function randomInt(int $min, int $max): int
    {
        return mt_rand($min, $max);
    }

    /**
     * Applies a small number of random point mutations (byte flip, byte deletion, or random-byte
     * insertion) to a known-good fixture, so the result stays "close" to valid input — much more
     * likely to hit a parser's interesting near-valid edge cases than fully random bytes.
     */
    private function mutate(string $base, int $mutationCount): string
    {
        $bytes = $base;
        for ($m = 0; $m < $mutationCount; $m++) {
            if ($bytes === '') {
                $bytes = random_bytes(1);
                continue;
            }
            $pos = $this->randomInt(0, strlen($bytes) - 1);
            $kind = $this->randomInt(0, 2);
            $bytes = match ($kind) {
                0 => substr($bytes, 0, $pos) . chr($this->randomInt(0, 255)) . substr($bytes, $pos + 1),
                1 => substr($bytes, 0, $pos) . substr($bytes, $pos + 1),
                default => substr($bytes, 0, $pos) . random_bytes($this->randomInt(1, 4)) . substr($bytes, $pos),
            };
        }
        return $bytes;
    }
}
