<?php

namespace SytxLabs\FileSanitizer\Tests\Decoder;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\AsciiHexDecoder;

final class AsciiHexDecoderTest extends TestCase
{
    public function testSupportsAsciiHexFilterNamesOnly(): void
    {
        $decoder = new AsciiHexDecoder();

        self::assertTrue($decoder->supports('ASCIIHexDecode'));
        self::assertTrue($decoder->supports('AHx'));
        self::assertFalse($decoder->supports('FlateDecode'));
    }

    public function testDecodesHexEncodedDataWithEodMarker(): void
    {
        $hex = bin2hex('hello world') . '>';

        self::assertSame('hello world', (new AsciiHexDecoder())->decode($hex));
    }

    public function testPadsOddLengthHexString(): void
    {
        self::assertSame("\xAB\xC0", (new AsciiHexDecoder())->decode('abc'));
    }
}
