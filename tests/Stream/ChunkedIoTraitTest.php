<?php

namespace SytxLabs\FileSanitizer\Tests\Stream;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Stream\ChunkedIoTrait;

/**
 * ChunkedIoTrait's methods are private, used only by the scanner/sanitizer classes that compose it.
 * Testing them directly through a harness that exposes each method (rather than only incidentally
 * through those consumers) makes every chunk-boundary and buffer-limit branch independently
 * reachable and asserts the trait's real contract: streams that return short reads, not just
 * whole-file-at-once reads.
 */
final class ChunkedIoTraitTest extends TestCase
{
    public function testCopyRangeWritesAcrossMultipleShortReads(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['abc', 'de']);
        $out = $this->output();

        $harness->doCopyRange($in, $out, 5, 3);

        self::assertSame('abcde', $out->buffer);
    }

    public function testCopyRangeStopsWhenStreamReturnsFalseBeforeLengthReached(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['ab']);
        $out = $this->output();

        $harness->doCopyRange($in, $out, 5);

        self::assertSame('ab', $out->buffer);
    }

    public function testCopyRangeStopsOnEmptyPiece(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['']);
        $out = $this->output();

        $harness->doCopyRange($in, $out, 5);

        self::assertSame('', $out->buffer);
    }

    public function testReadExactAccumulatesAcrossMultipleShortReads(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['ab', 'cd', 'ef']);

        self::assertSame('abcdef', $harness->doReadExact($in, 6));
    }

    public function testReadExactReturnsPartialDataWhenStreamEndsEarly(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['ab']);

        self::assertSame('ab', $harness->doReadExact($in, 5));
    }

    public function testReadExactReturnsEmptyStringOnImmediateEmptyPiece(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['']);

        self::assertSame('', $harness->doReadExact($in, 5));
    }

    public function testScanRangeForPatternsFindsPatternWithinASingleChunk(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['hello ', 'JS:xxx']);

        $found = $harness->doScanRangeForPatterns($in, 12, ['js' => '/JS:/'], 1048576, 2);

        self::assertSame(['js'], $found);
    }

    public function testScanRangeForPatternsFindsPatternSplitAcrossChunkBoundaryViaOverlap(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['abcJ', 'Sxyz']);

        $found = $harness->doScanRangeForPatterns($in, 8, ['js' => '/JS/'], 1048576, 3);

        self::assertSame(['js'], $found);
    }

    public function testScanRangeForPatternsReturnsEmptyWhenNothingMatches(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['nothing', 'to find']);

        self::assertSame([], $harness->doScanRangeForPatterns($in, 14, ['js' => '/JS:/']));
    }

    public function testScanRangeForPatternsDoesNotDuplicateAnAlreadyFoundCode(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['JS one ', 'JS two']);

        $found = $harness->doScanRangeForPatterns($in, 13, ['js' => '/JS/']);

        self::assertSame(['js'], $found);
    }

    public function testScanRangeForPatternsStopsWhenStreamEndsBeforeLengthReached(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['x']);

        self::assertSame([], $harness->doScanRangeForPatterns($in, 100, ['js' => '/JS/']));
    }

    public function testCopyRangeWithPatternDetectionCopiesEveryPieceRegardlessOfMatch(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['no', 'match', 'here']);
        $out = $this->output();
        $matched = false;

        $harness->doCopyRangeWithPatternDetection($in, $out, 11, '/JS/', $matched);

        self::assertSame('nomatchhere', $out->buffer);
        self::assertFalse($matched);
    }

    public function testCopyRangeWithPatternDetectionFindsPatternSplitAcrossChunks(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['abcJ', 'Sxyz']);
        $out = $this->output();
        $matched = false;

        $harness->doCopyRangeWithPatternDetection($in, $out, 8, '/JS/', $matched, 1048576, 3);

        self::assertSame('abcJSxyz', $out->buffer);
        self::assertTrue($matched);
    }

    public function testCopyRangeWithPatternDetectionSkipsScanningWhenAlreadyMatched(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['abc', 'def']);
        $out = $this->output();
        $matched = true;

        $harness->doCopyRangeWithPatternDetection($in, $out, 6, '/JS/', $matched);

        self::assertSame('abcdef', $out->buffer);
        self::assertTrue($matched);
    }

    public function testCopyRangeWithPatternDetectionStopsOnEmptyPiece(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['']);
        $out = $this->output();
        $matched = false;

        $harness->doCopyRangeWithPatternDetection($in, $out, 5, '/JS/', $matched);

        self::assertSame('', $out->buffer);
        self::assertFalse($matched);
    }

    public function testStreamStripPatternsRemovesMatchAndSetsAnyRemoved(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['xxBADyy']);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, 7, '/BAD/', [], $anyRemoved);

        self::assertSame('xxyy', $out->buffer);
        self::assertTrue($anyRemoved);
    }

    public function testStreamStripPatternsLeavesAnyRemovedFalseWhenNothingMatches(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['hello']);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, 5, '/ZZZ/', [], $anyRemoved);

        self::assertSame('hello', $out->buffer);
        self::assertFalse($anyRemoved);
    }

    /**
     * An open-marker match holds everything from its offset back as carry instead of writing it,
     * so a construct that is still incomplete at a chunk boundary (here "<scr" ahead of "ipt>")
     * never gets flushed half-formed; the next chunk completes it before the strip pattern runs.
     */
    public function testStreamStripPatternsCarriesIncompleteConstructAcrossChunkBoundary(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['AAA<scr', 'ipt>BBB']);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, 14, '/<script>/', ['/<scr/'], $anyRemoved);

        self::assertSame('AAABBB', $out->buffer);
        self::assertTrue($anyRemoved);
    }

    /**
     * maxCarry is a defensive cap: even when an open-marker match would hold back an entire chunk,
     * the carried region cannot exceed maxCarry bytes, so the boundary is forced forward and the
     * excess is written out anyway (still byte-for-byte correct once the final carry is flushed).
     */
    public function testStreamStripPatternsClampsCarryToMaxCarry(): void
    {
        $harness = $this->harness();
        $content = '<scr' . str_repeat('A', 20);
        $in = $this->stream([$content]);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, strlen($content), '/ZZZ/', ['/<scr/'], $anyRemoved, 1048576, 5);

        self::assertSame($content, $out->buffer);
    }

    /**
     * A malformed pattern makes preg_replace() return null; the trait must fall back to the
     * unmodified window rather than propagate that null as content. The @ here suppresses the
     * PHP warning preg_replace() raises for the broken pattern, the same way a caller running
     * outside PHPUnit's strict warning-to-exception handler would experience it.
     */
    public function testStreamStripPatternsFallsBackToOriginalWindowWhenPatternIsInvalid(): void
    {
        $harness = $this->harness();
        $content = '<scrAAAA';
        $in = $this->stream([$content]);
        $out = $this->output();
        $anyRemoved = false;

        @$harness->doStreamStripPatterns($in, $out, strlen($content), '/[/', ['/<scr/'], $anyRemoved);

        self::assertSame($content, $out->buffer);
        self::assertFalse($anyRemoved);
    }

    /**
     * When an open-marker match holds back the rest of a chunk as carry all the way to the end of
     * input, the pattern replacement on that leftover only happens in the post-loop trailing flush,
     * not inside the main loop; anyRemoved must still be set true there when it actually changes
     * something.
     */
    public function testStreamStripPatternsSetsAnyRemovedWhenTheTrailingFlushActuallyChangesTheCarry(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['X<scrBADtext']);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, 12, '/BAD/', ['/<scr/'], $anyRemoved);

        self::assertSame('X<scrtext', $out->buffer);
        self::assertTrue($anyRemoved);
    }

    public function testStreamStripPatternsStopsWhenStreamEndsImmediately(): void
    {
        $harness = $this->harness();
        $in = $this->stream(['']);
        $out = $this->output();
        $anyRemoved = false;

        $harness->doStreamStripPatterns($in, $out, 10, '/BAD/', [], $anyRemoved);

        self::assertSame('', $out->buffer);
        self::assertFalse($anyRemoved);
    }

    private function harness(): object
    {
        return new class
        {
            use ChunkedIoTrait;

            public function doCopyRange(StreamInterface $in, OutputInterface $out, int $length, int $bufferSize = 1048576): void
            {
                $this->copyRange($in, $out, $length, $bufferSize);
            }

            public function doReadExact(StreamInterface $in, int $length): string
            {
                return $this->readExact($in, $length);
            }

            /**
             * @param array<string, string> $patterns
             * @return list<string>
             */
            public function doScanRangeForPatterns(StreamInterface $in, int $length, array $patterns, int $bufferSize = 1048576, int $overlap = 256): array
            {
                return $this->scanRangeForPatterns($in, $length, $patterns, $bufferSize, $overlap);
            }

            public function doCopyRangeWithPatternDetection(StreamInterface $in, OutputInterface $out, int $length, string $pattern, bool &$matchedAny, int $bufferSize = 1048576, int $overlap = 256): void
            {
                $this->copyRangeWithPatternDetection($in, $out, $length, $pattern, $matchedAny, $bufferSize, $overlap);
            }

            /** @param list<string> $openMarkerPatterns */
            public function doStreamStripPatterns(StreamInterface $in, OutputInterface $out, int $length, string $pattern, array $openMarkerPatterns, bool &$anyRemoved, int $bufferSize = 1048576, int $maxCarry = 4194304, string $replacement = ''): void
            {
                $this->streamStripPatterns($in, $out, $length, $pattern, $openMarkerPatterns, $anyRemoved, $bufferSize, $maxCarry, $replacement);
            }
        };
    }

    /** @param list<string> $chunks */
    private function stream(array $chunks): StreamInterface
    {
        return new class ('', $chunks) implements StreamInterface
        {
            private int $index = 0;

            /** @param list<string> $chunks */
            public function __construct(string $path, private readonly array $chunks = [])
            {
            }

            public function filePath(): string
            {
                return '';
            }

            public function read(int $length): false|string
            {
                if ($this->index >= count($this->chunks)) {
                    return false;
                }
                return $this->chunks[$this->index++];
            }

            public function eof(): bool
            {
                return $this->index >= count($this->chunks);
            }

            public function tell(): false|int
            {
                return 0;
            }

            public function size(): false|int
            {
                return 0;
            }

            public function seek(int $offset): void
            {
            }

            public function rewind(): void
            {
                $this->index = 0;
            }

            public function close(): void
            {
            }
        };
    }

    private function output(): OutputInterface
    {
        return new class ('') implements OutputInterface
        {
            public string $buffer = '';

            public function __construct(string $path)
            {
            }

            public function write(string $data): void
            {
                $this->buffer .= $data;
            }

            public function close(): void
            {
            }

            public function size(): false|int
            {
                return strlen($this->buffer);
            }
        };
    }
}
