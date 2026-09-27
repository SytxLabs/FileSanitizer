<?php

namespace SytxLabs\FileSanitizer\Contracts;

interface StreamInterface
{
    public function __construct(string $path);

    public function filePath(): string;

    public function read(int $length): false|string;

    public function eof(): bool;

    public function tell(): false|int;

    public function size(): false|int;

    public function seek(int $offset): void;

    public function rewind(): void;

    public function close(): void;
}
