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
     *
     * @param list<int> $codes
     */
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
