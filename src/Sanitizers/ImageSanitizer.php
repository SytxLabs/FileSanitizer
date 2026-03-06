<?php

namespace SytxLabs\FileSanitizer\Sanitizers;

use Intervention\Image\ImageManager;
use SytxLabs\FileSanitizer\Exception\SanitizerException;

class ImageSanitizer
{
    public function sanitize(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("Image not found or unreadable: {$inputPath}");
        }

        $extension = strtolower(pathinfo($outputPath, PATHINFO_EXTENSION));

        $manager = ImageManager::gd();
        $image = $manager->read($inputPath);

        match ($extension) {
            'png' => $image->toPng()->save($outputPath),
            'gif' => $image->toGif()->save($outputPath),
            'webp' => $image->toWebp(90)->save($outputPath),
            default => $image->toJpeg(90)->save($outputPath),
        };

        if (!is_file($outputPath) || filesize($outputPath) === 0) {
            throw new SanitizerException("Failed to write sanitized image: {$outputPath}");
        }
    }
}
