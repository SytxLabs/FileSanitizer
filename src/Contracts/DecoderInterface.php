<?php

namespace SytxLabs\FileSanitizer\Contracts;

interface DecoderInterface
{
    public function supports(string $filter): bool;

    public function decode(string $data): string;
}
