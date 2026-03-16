<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use Exception;
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
        $issues = [];
        if ($type === IMAGETYPE_PNG) {
            $iccpWarningSeen = false;

            set_error_handler(static function (int $severity, string $message) use (&$iccpWarningSeen): bool {
                if ($severity === E_WARNING && str_contains($message, 'imagecreatefrompng()') && str_contains($message, 'iCCP: known incorrect sRGB profile')) {
                    $iccpWarningSeen = true;
                    return true; // bekannte libpng-Warnung lokal unterdruecken
                }
                return false; // alles andere normal weiterreichen
            });
            try {
                $image = imagecreatefrompng($inputPath);
            } finally {
                restore_error_handler();
            }
            if ($iccpWarningSeen) {
                $issues[] = new Issue('png_iccp_profile_warning', 'The PNG file contains a corrupted iCCP/sRGB profile; the file was decoded anyway and will be re-encoded.', IssueSeverity::Warning);
            }
        } else {
            $image = match ($type) {
                IMAGETYPE_JPEG => imagecreatefromjpeg($inputPath),
                IMAGETYPE_GIF => imagecreatefromgif($inputPath),
                IMAGETYPE_WEBP => function_exists('imagecreatefromwebp') ? imagecreatefromwebp($inputPath) : false,
                default => false,
            };
        }

        if ($image === false) {
            throw new RuntimeException('Could not decode image for metadata stripping.');
        }
        try {
            if (!file_exists(dirname($outputPath))) {
                mkdir(dirname($outputPath), 0755, true);
            }
        } catch (Exception $e) {
            throw new RuntimeException('Failed to create output directory: ' . $e->getMessage());
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
        $issues[] = new Issue('image_reencoded', 'Image was re-encoded to strip metadata and ancillary chunks.', IssueSeverity::Info);
        return new SanitizeReport($outputPath, true, $issues);
    }
}
