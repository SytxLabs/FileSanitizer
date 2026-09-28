<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class ImageSanitizer implements SanitizerInterface
{
    /**
     * ImageSanitizer works directly on the input/output file paths via GD, so unlike the other
     * sanitizers it never touches the injected stream/writer/options; they exist only to satisfy
     * SanitizerInterface's constructor signature for uniform DI-based instantiation.
     *
     * @param array<string, mixed>|null $options
     */
    public function __construct(?StreamInterface $stream = null, ?OutputInterface $output = null, ?array $options = null)
    {
    }

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

        $hadMetadata = $this->hasMetadataMarkers($inputPath, $type);

        $issues = [];
        if (!file_exists(dirname($outputPath)) && !mkdir(dirname($outputPath), 0755, true) && !is_dir(dirname($outputPath))) {
            throw new RuntimeException('Failed to create output directory.');
        }

        $warning = null;
        if ($type === IMAGETYPE_PNG) {
            set_error_handler(static function (int $severity, string $message) use (&$warning) {
                $warning = $message;
                return true;
            });
            try {
                $source = imagecreatefrompng($inputPath);
            } finally {
                restore_error_handler();
            }
            if ($source === false) {
                throw new RuntimeException('Could not decode PNG for metadata stripping.' . ($warning ? ' ' . $warning : ''));
            }

            $width = imagesx($source);
            $height = imagesy($source);

            $image = imagecreatetruecolor($width, $height);
            if ($image === false) {
                imagedestroy($source);
                throw new RuntimeException('Could not create PNG target image.');
            }
            imagealphablending($image, false);
            imagesavealpha($image, true);
            $transparent = imagecolorallocatealpha($image, 0, 0, 0, 127);
            if ($transparent === false) {
                imagedestroy($source);
                imagedestroy($image);
                throw new RuntimeException('Could not allocate transparent color for PNG target image.');
            }
            imagefilledrectangle($image, 0, 0, $width, $height, $transparent);
            if (!imagecopy($image, $source, 0, 0, 0, 0, $width, $height)) {
                imagedestroy($source);
                imagedestroy($image);
                throw new RuntimeException('Could not copy PNG pixels.');
            }
            imagedestroy($source);
        } else {
            $image = match ($type) {
                IMAGETYPE_JPEG => imagecreatefromjpeg($inputPath),
                IMAGETYPE_GIF => imagecreatefromgif($inputPath),
                IMAGETYPE_WEBP => function_exists('imagecreatefromwebp') ? imagecreatefromwebp($inputPath) : false,
                default => false,
            };

            if ($image === false) {
                throw new RuntimeException('Could not decode image for metadata stripping.');
            }
        }

        $success = match ($type) {
            IMAGETYPE_JPEG => imagejpeg($image, $outputPath),
            IMAGETYPE_PNG => imagepng($image, $outputPath),
            IMAGETYPE_GIF => imagegif($image, $outputPath),
            IMAGETYPE_WEBP => function_exists('imagewebp') && imagewebp($image, $outputPath),
            default => false,
        };

        imagedestroy($image);

        if ($success !== true) {
            throw new RuntimeException('Could not re-encode image.');
        }
        if ($warning !== null) {
            $issues[] = new Issue('png_metadata_warning', $warning, IssueSeverity::Warning);
        }
        $issues[] = new Issue('image_reencoded', 'Image was re-encoded to strip metadata and ancillary chunks.', IssueSeverity::Info);

        return new SanitizeReport($outputPath, $hadMetadata && !$this->hasMetadataMarkers($outputPath, $type), $issues);
    }

    private function hasMetadataMarkers(string $path, int $type): bool
    {
        $bytes = @file_get_contents($path);
        if ($bytes === false) {
            return false;
        }

        return match ($type) {
            IMAGETYPE_JPEG => str_contains($bytes, "Exif\x00\x00") || str_contains($bytes, 'http://ns.adobe.com/xap') || str_contains($bytes, 'Photoshop 3.0'),
            IMAGETYPE_PNG => preg_match('/(?:tEXt|zTXt|iTXt|eXIf)/', $bytes) === 1,
            IMAGETYPE_GIF => str_contains($bytes, "\x21\xFE"),
            IMAGETYPE_WEBP => str_contains($bytes, 'EXIF') || str_contains($bytes, 'XMP '),
            default => false,
        };
    }
}
