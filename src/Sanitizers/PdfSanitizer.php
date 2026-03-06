<?php

namespace SytxLabs\FileSanitizer\Sanitizers;

use SytxLabs\FileSanitizer\Exception\SanitizerException;
use setasign\Fpdi\Fpdi;
use setasign\Fpdi\PdfParser\CrossReference\CrossReferenceException;
use setasign\Fpdi\PdfParser\PdfParserException;
use Throwable;

class PdfSanitizer
{
    public function sanitize(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("PDF not found or unreadable: {$inputPath}");
        }

        try {
            $pdf = new Fpdi();

            $pdf->SetCreator('');
            $pdf->SetAuthor('');
            $pdf->SetTitle('');
            $pdf->SetSubject('');
            $pdf->SetKeywords('');

            $pageCount = $pdf->setSourceFile($inputPath);

            for ($pageNo = 1; $pageNo <= $pageCount; $pageNo++) {
                $templateId = $pdf->importPage($pageNo, '/CropBox', true, false);
                $size = $pdf->getTemplateSize($templateId);

                $orientation = $size['width'] > $size['height'] ? 'L' : 'P';
                $pdf->AddPage($orientation, [$size['width'], $size['height']]);
                $pdf->useTemplate($templateId);
            }

            $pdf->Output('F', $outputPath);

            if (!is_file($outputPath) || filesize($outputPath) === 0) {
                throw new SanitizerException("Failed to write sanitized PDF: {$outputPath}");
            }
        } catch (CrossReferenceException|PdfParserException $e) {
            throw new SanitizerException('PDF parsing failed. The file is likely malformed, incomplete, encrypted, or not fully compatible with FPDI: ' . $e->getMessage(), previous: $e);
        } catch (Throwable $e) {
            throw new SanitizerException('Unexpected PDF sanitizer error: ' . $e->getMessage(), previous: $e);
        }
    }
}