<?php

namespace SytxLabs\FileSanitizer\Tests\Decoder;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Decoder\RunLengthDecoder;

final class RunLengthDecoderTest extends TestCase
{
    public function testSupportsRunLengthFilterNamesOnly(): void
    {
        $decoder = new RunLengthDecoder();

        self::assertTrue($decoder->supports('RunLengthDecode'));
        self::assertTrue($decoder->supports('RL'));
        self::assertFalse($decoder->supports('FlateDecode'));
    }

    public function testDecodesRepeatedByteRun(): void
    {
        $encoded = chr(253) . 'A';

        self::assertSame('AAAA', (new RunLengthDecoder())->decode($encoded));
    }

    public function testDecodesLiteralByteRun(): void
    {
        $encoded = chr(2) . 'XYZ';

        self::assertSame('XYZ', (new RunLengthDecoder())->decode($encoded));
    }
}
