<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class PdfSanitizer implements SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool
    {
        return $mimeType === 'application/pdf' || str_ends_with(strtolower($path), '.pdf');
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $content = file_get_contents($inputPath);
        if ($content === false) {
            throw new RuntimeException('Could not read PDF.');
        }

        $issues = [];
        $original = $content;
        $activePattern = '/\/JavaScript\b|\/JS\b|\/OpenAction\b|\/AA\b/i';
        $hadActiveContent = preg_match($activePattern, $content) === 1;

        if ($hadActiveContent) {
            if (!$sanitizeAlways) {
                throw new RuntimeException('PDF contains active content and was rejected. Call process($inputPath, $outputPath, true) to sanitize anyway.');
            }

            $content = preg_replace('/\/OpenAction\s+(?:\d+\s+\d+\s+R|<<.*?>>|\[.*?\])/is', '', $content) ?? $content;
            $content = preg_replace('/\/AA\s*<<.*?>>/is', '', $content) ?? $content;
            $content = preg_replace('/\/JavaScript\s+(?:\d+\s+\d+\s+R|\(.*?\)|<<.*?>>)/is', '', $content) ?? $content;
            $content = preg_replace('/\/JS\s+(?:\(.*?\)|<.*?>|\d+\s+\d+\s+R)/is', '/JS ()', $content) ?? $content;

            $issues[] = new Issue(
                'pdf_active_content_removed',
                'PDF contained active-content markers; best-effort cleanup removed common action and JavaScript references.',
                IssueSeverity::Warning
            );
        }

        $content = preg_replace('/<\?xpacket.*?<\/x:xmpmeta>\s*<\?xpacket end="w"\?>/is', '', $content) ?? $content;
        $content = preg_replace('/\/(Title|Author|Subject|Keywords|Creator|Producer|CreationDate|ModDate)\s*\((?:\\.|[^()])*\)/i', '/$1 ()', $content) ?? $content;

        if (file_put_contents($outputPath, $content) === false) {
            throw new RuntimeException('Could not write sanitized PDF.');
        }

        $issues[] = new Issue(
            'pdf_best_effort_cleanup',
            $hadActiveContent
                ? 'PDF was sanitized in best-effort mode; common active-content markers and metadata fields were removed or blanked.'
                : 'PDF metadata cleanup is best-effort only; common metadata fields were blanked.',
            IssueSeverity::Info
        );

        return new SanitizeReport($outputPath, $original !== $content, $issues);
    }
}
