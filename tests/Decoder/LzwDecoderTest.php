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
}
