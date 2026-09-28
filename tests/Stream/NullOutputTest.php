<?php

namespace SytxLabs\FileSanitizer\Tests\Stream;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Stream\NullOutput;

final class NullOutputTest extends TestCase
{
    public function testDiscardsAllWrites(): void
    {
        $output = new NullOutput('/does/not/matter.bin');

        $output->write('some data');
        self::assertSame(0, $output->size());

        $output->close();
    }
}
