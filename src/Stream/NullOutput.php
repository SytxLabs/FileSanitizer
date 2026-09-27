<?php

namespace SytxLabs\FileSanitizer\Stream;

use SytxLabs\FileSanitizer\Contracts\OutputInterface;

final class NullOutput implements OutputInterface
{
    public function __construct(string $path)
    {
    }

    public function write(string $data): void
    {
    }

    public function close(): void
    {
    }

    public function size(): false|int
    {
        return 0;
    }
}
