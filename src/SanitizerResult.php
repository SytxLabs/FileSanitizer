<?php

namespace SytxLabs\FileSanitizer;

use JsonSerializable;

class SanitizerResult implements JsonSerializable
{
    public function __construct(
        public readonly string $inputPath,
        public readonly string $outputPath,
        public readonly string $mimeType,
        public readonly string $sanitizer,
        public readonly int $originalSize,
        public readonly int $sanitizedSize,
        public readonly string $originalSha256,
        public readonly string $sanitizedSha256
    ) {
    }

    public function toArray(): array
    {
        return [
            'input_path' => $this->inputPath,
            'output_path' => $this->outputPath,
            'mime_type' => $this->mimeType,
            'sanitizer' => $this->sanitizer,
            'original_size' => $this->originalSize,
            'sanitized_size' => $this->sanitizedSize,
            'original_sha256' => $this->originalSha256,
            'sanitized_sha256' => $this->sanitizedSha256,
        ];
    }

    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
