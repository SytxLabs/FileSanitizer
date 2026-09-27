<?php

namespace SytxLabs\FileSanitizer\Tests\Decoder;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\Ascii85Decoder;

final class Ascii85DecoderTest extends TestCase
{
    public function testSupportsAscii85FilterNamesOnly(): void
    {
        $decoder = new Ascii85Decoder();

        self::assertTrue($decoder->supports('ASCII85Decode'));
        self::assertTrue($decoder->supports('A85'));
        self::assertFalse($decoder->supports('FlateDecode'));
    }

    public function testDecodesZeroShorthand(): void
    {
        self::assertSame("\0\0\0\0", (new Ascii85Decoder())->decode('<~z~>'));
    }

    public function testReturnsInputUnchangedOnInvalidCharacter(): void
    {
        $garbage = '{invalid}';

        self::assertSame($garbage, (new Ascii85Decoder())->decode($garbage));
    }
}
