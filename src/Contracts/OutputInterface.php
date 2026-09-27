<?php

namespace SytxLabs\FileSanitizer\Contracts;

interface OutputInterface
{
    public function __construct(string $path);

    public function write(string $data): void;

    public function close(): void;

    public function size(): false|int;
}
