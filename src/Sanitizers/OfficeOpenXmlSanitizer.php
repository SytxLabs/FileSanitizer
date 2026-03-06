<?php

namespace SytxLabs\FileSanitizer\Sanitizers;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SytxLabs\FileSanitizer\Exception\SanitizerException;
use ZipArchive;

class OfficeOpenXmlSanitizer
{
    public function sanitize(string $inputPath, string $outputPath): void
    {
        if (!is_file($inputPath) || !is_readable($inputPath)) {
            throw new SanitizerException("Office file not found or unreadable: {$inputPath}");
        }

        $tempDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'sanitize_' . bin2hex(random_bytes(8));

        if (!mkdir($tempDir, 0777, true) && !is_dir($tempDir)) {
            throw new SanitizerException("Failed to create temp directory: {$tempDir}");
        }

        $zip = new ZipArchive();

        if ($zip->open($inputPath) !== true) {
            $this->deleteDirectory($tempDir);
            throw new SanitizerException("Could not open Office file: {$inputPath}");
        }

        $zip->extractTo($tempDir);
        $zip->close();

        @unlink($tempDir . '/docProps/core.xml');
        @unlink($tempDir . '/docProps/app.xml');
        @unlink($tempDir . '/docProps/custom.xml');

        $newZip = new ZipArchive();

        if ($newZip->open($outputPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
            $this->deleteDirectory($tempDir);
            throw new SanitizerException("Could not create sanitized Office file: {$outputPath}");
        }

        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($tempDir, FilesystemIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile()) {
                $absolutePath = $file->getRealPath();
                $relativePath = substr($absolutePath, strlen($tempDir) + 1);
                $newZip->addFile($absolutePath, str_replace('\\', '/', $relativePath));
            }
        }

        $newZip->close();
        $this->deleteDirectory($tempDir);

        if (!is_file($outputPath) || filesize($outputPath) === 0) {
            throw new SanitizerException("Failed to write sanitized Office file: {$outputPath}");
        }
    }

    private function deleteDirectory(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $items = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
            RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($items as $item) {
            if ($item->isDir()) {
                rmdir($item->getRealPath());
            } else {
                unlink($item->getRealPath());
            }
        }

        rmdir($directory);
    }
}
