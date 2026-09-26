<?php

namespace SytxLabs\FileSanitizer\Tests\Decoder;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\FlateDecoder;

final class FlateDecoderTest extends TestCase
{
    public function testSupportsFlateDecodeFilterNamesOnly(): void
    {
        $decoder = new FlateDecoder();

        self::assertTrue($decoder->supports('FlateDecode'));
        self::assertTrue($decoder->supports('/FlateDecode'));
        self::assertTrue($decoder->supports('Fl'));
        self::assertFalse($decoder->supports('ASCIIHexDecode'));
    }

    public function testDecodesZlibCompressedData(): void
    {
        $original = 'hidden /JavaScript payload';
        $compressed = gzcompress($original);

        self::assertSame($original, (new FlateDecoder())->decode($compressed));
    }

    public function testReturnsInputUnchangedWhenNotDecodable(): void
    {
        $garbage = 'not compressed data';

        self::assertSame($garbage, (new FlateDecoder())->decode($garbage));
    }
}
