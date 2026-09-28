<?php

namespace SytxLabs\FileSanitizer\Tests\Stream;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Stream\NullStream;

final class NullStreamTest extends TestCase
{
    public function testActsAsAnInertStreamThatReportsImmediateEof(): void
    {
        $stream = new NullStream('/does/not/matter.bin');

        self::assertSame('/does/not/matter.bin', $stream->filePath());
        self::assertFalse($stream->read(10));
        self::assertTrue($stream->eof());
        self::assertSame(0, $stream->tell());
        self::assertSame(0, $stream->size());

        $stream->seek(5);
        $stream->rewind();
        $stream->close();
    }
}
