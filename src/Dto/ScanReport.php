<?php

namespace SytxLabs\FileSanitizer\Dto;

use JsonSerializable;
use Stringable;

final class ScanReport implements JsonSerializable, Stringable
{
    /** @param array<Issue> $issues */
    public function __construct(public readonly bool $safe, public readonly array $issues = [])
    {
    }

    public function __toString(): string
    {
        return $this->safe ? 'yes' : 'no';
    }

    public static function clean(): self
    {
        return new self(true, []);
    }

    /** @param list<Issue> $issues */
    public static function unsafe(array $issues): self
    {
        return new self(false, $issues);
    }

    public function toArray(): array
    {
        return [
            'safe' => $this->safe,
            'issues' => $this->issues,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
