<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class ImageSanitizer implements SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool
    {
        return in_array($mimeType, ['image/jpeg', 'image/png', 'image/gif', 'image/webp'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $type = exif_imagetype($inputPath);
        if ($type === false) {
            throw new RuntimeException('Unsupported image file.');
        }

        $image = match ($type) {
            IMAGETYPE_JPEG => imagecreatefromjpeg($inputPath),
            IMAGETYPE_PNG => imagecreatefrompng($inputPath),
            IMAGETYPE_GIF => imagecreatefromgif($inputPath),
            IMAGETYPE_WEBP => function_exists('imagecreatefromwebp') ? imagecreatefromwebp($inputPath) : false,
            default => false,
        };

        if ($image === false) {
            throw new RuntimeException('Could not decode image for metadata stripping.');
        }

        $success = match ($type) {
            IMAGETYPE_JPEG => imagejpeg($image, $outputPath, 92),
            IMAGETYPE_PNG => imagepng($image, $outputPath, 6),
            IMAGETYPE_GIF => imagegif($image, $outputPath),
            IMAGETYPE_WEBP => function_exists('imagewebp') && imagewebp($image, $outputPath, 90),
            default => false,
        };

        imagedestroy($image);

        if ($success !== true) {
            throw new RuntimeException('Could not re-encode image.');
        }

        return new SanitizeReport($outputPath, true, [
            new Issue('image_reencoded', 'Image was re-encoded to strip metadata and ancillary chunks.', IssueSeverity::Info),
        ]);
    }
}
