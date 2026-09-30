<?php

namespace SytxLabs\FileSanitizer\Tests\Decoder;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\LzwDecoder;

final class LzwDecoderTest extends TestCase
{
    public function testSupportsLzwFilterNamesOnly(): void
    {
        $decoder = new LzwDecoder();

        self::assertTrue($decoder->supports('LZWDecode'));
        self::assertTrue($decoder->supports('LZW'));
        self::assertFalse($decoder->supports('FlateDecode'));
    }

    public function testDecodesLiteralByteFollowedByEndOfData(): void
    {
        // 9-bit codes [65 ('A'), 257 (EOD)] packed MSB-first into 3 bytes: 0x20 0xC0 0x40.
        $encoded = "\x20\xC0\x40";

        self::assertSame('A', (new LzwDecoder())->decode($encoded));
    }

    public function testReturnsInputUnchangedOnInvalidCode(): void
    {
        $garbage = "\xFF\xFF\xFF";

        self::assertSame($garbage, (new LzwDecoder())->decode($garbage));
    }

    public function testClearCodeResetsTheTableAndContinuesDecoding(): void
    {
        // Codes: 'A' (65), clear-table (256), 'B' (66), end-of-data (257); all 9-bit.
        $encoded = $this->packCodes([65, 256, 66, 257]);

        self::assertSame('AB', (new LzwDecoder())->decode($encoded));
    }

    /**
     * The "KwKwK" case: a code equal to the table's next free slot, referencing an entry that
     * hasn't been added yet. Per the LZW algorithm this always means "the previous entry followed
     * by its own first character" — reachable on the very first back-reference, since nextCode
     * starts at 258 before any entry has been added.
     */
    public function testHandlesCodeEqualToNextFreeTableSlot(): void
    {
        // Codes: 'A' (65), then 258 (== initial nextCode, not yet in the table), end-of-data (257).
        $encoded = $this->packCodes([65, 258, 257]);

        // 'A' from the first code, then 'A'.'A'[0]='AA' from the KwKwK entry: "A" + "AA" = "AAA".
        self::assertSame('AAA', (new LzwDecoder())->decode($encoded));
    }

    /**
     * Packs fixed-width 9-bit LZW codes MSB-first into a byte stream, matching how decode() itself
     * unpacks: accumulate bits, then peel off codeLen-bit chunks from the top once enough have
     * built up. Trailing bits are zero-padded; decode() never reaches them here because every
     * sequence below ends on an explicit end-of-data code (257), which returns immediately.
     */
    public function testCodeWidthGrowsWhenTheTableOutgrowsNineBits(): void
    {
        $expected = '';
        $codes = [256];
        for ($i = 0; $i < 600; $i++) {
            $expected .= chr($i % 251);
            $codes[] = $i % 251;
        }
        $codes[] = 257;

        // Mirror the decoder's early-change rule: the first code after the clear adds no table
        // entry, every later one does, and the width grows once nextCode + 1 reaches 1 << width.
        $bitBuffer = 0;
        $bitCount = 0;
        $width = 9;
        $nextCode = 258;
        $encoded = '';
        foreach ($codes as $index => $code) {
            $bitBuffer = (($bitBuffer << $width) | $code) & 0xFFFFFFFF;
            $bitCount += $width;
            while ($bitCount >= 8) {
                $bitCount -= 8;
                $encoded .= chr(($bitBuffer >> $bitCount) & 0xFF);
            }
            if ($index >= 2 && $code !== 257) {
                $nextCode++;
                if ($nextCode + 1 >= (1 << $width) && $width < 12) {
                    $width++;
                }
            }
        }
        if ($bitCount > 0) {
            $encoded .= chr(($bitBuffer << (8 - $bitCount)) & 0xFF);
        }

        self::assertSame($expected, (new LzwDecoder())->decode($encoded));
    }

    private function packCodes(array $codes, int $codeLen = 9): string
    {
        $bitBuffer = 0;
        $bitCount = 0;
        $out = '';
        foreach ($codes as $code) {
            $bitBuffer = ($bitBuffer << $codeLen) | $code;
            $bitCount += $codeLen;
            while ($bitCount >= 8) {
                $bitCount -= 8;
                $out .= chr(($bitBuffer >> $bitCount) & 0xFF);
            }
        }
        if ($bitCount > 0) {
            $out .= chr(($bitBuffer << (8 - $bitCount)) & 0xFF);
        }
        return $out;
    }
}
