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

    /** @return array<string, array{0: string}> */
    public static function roundTripProvider(): array
    {
        return [
            'exact multiple of 4 bytes' => ['abcd'],
            'one leftover byte' => ['abcde'],
            'two leftover bytes' => ['abcdef'],
            'three leftover bytes' => ['hello world'],
        ];
    }

    /** @dataProvider roundTripProvider */
    public function testDecodesRealEncodedDataWithATailNotAMultipleOfFive(string $original): void
    {
        $encoded = '<~' . $this->encode($original) . '~>';

        self::assertSame($original, (new Ascii85Decoder())->decode($encoded));
    }

    private function encode(string $data): string
    {
        $out = '';
        for ($i = 0, $len = strlen($data); $i < $len; $i += 4) {
            $chunk = substr($data, $i, 4);
            $n = strlen($chunk);
            $tuple = unpack('N', str_pad($chunk, 4, "\0"))[1];
            if ($n === 4 && $tuple === 0) {
                $out .= 'z';
                continue;
            }
            $chars = '';
            for ($j = 0; $j < 5; $j++) {
                $chars = chr(($tuple % 85) + 33) . $chars;
                $tuple = intdiv($tuple, 85);
            }
            $out .= substr($chars, 0, $n + 1);
        }
        return $out;
    }
}
