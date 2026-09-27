<?php

namespace SytxLabs\FileSanitizer\Stream;

use SytxLabs\FileSanitizer\Contracts\StreamInterface;

final class NullStream implements StreamInterface
{
    public function __construct(private readonly string $path)
    {
    }

    public function filePath(): string
    {
        return $this->path;
    }

    public function read(int $length): false|string
    {
        return false;
    }

    public function eof(): bool
    {
        return true;
    }

    public function tell(): false|int
    {
        return 0;
    }

    public function size(): false|int
    {
        return 0;
    }

    public function seek(int $offset): void
    {
    }

    public function rewind(): void
    {
    }

    public function close(): void
    {
    }
}
