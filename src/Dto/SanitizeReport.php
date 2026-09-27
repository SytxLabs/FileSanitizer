<?php

namespace SytxLabs\FileSanitizer\Dto;

use JsonSerializable;
use Stringable;

final class SanitizeReport implements JsonSerializable, Stringable
{
    /**
     * @param array<Issue> $issues
     */
    public function __construct(public readonly string $outputPath, public readonly bool $metadataRemoved, public readonly array $issues = [], public readonly array $context = [], public readonly bool $unchanged = false)
    {
    }

    public function __toString(): string
    {
        return $this->outputPath;
    }

    public function toArray(): array
    {
        return [
            'outputPath' => $this->outputPath,
            'metadataRemoved' => $this->metadataRemoved,
            'issues' => $this->issues,
            'context' => $this->context,
            'unchanged' => $this->unchanged,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
