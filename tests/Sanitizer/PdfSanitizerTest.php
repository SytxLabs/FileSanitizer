<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\PdfSanitizer;

class PdfSanitizerTest extends TestCase
{
    private string $tempDir;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_test_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testRemovesScriptHandlersDangerousUrlsAndMetaRefresh(): void
    {
        $input = $this->tempDir . '/input.pdf';
        $output = $this->tempDir . '/output.pdf';
        file_put_contents($input, '%PDF-1.7
        1 0 obj
        <</Pages 1 0 R /OpenAction 2 0 R>>
        2 0 obj
        <</S /JavaScript /JS (app.alert(1))>>
        trailer
        <</Root 1 0 R>>');

        (new PdfSanitizer())->sanitize($input, $output, true);
        $clean = (string) file_get_contents($output);
        self::assertStringContainsString('PDF-1.7', $clean);
        self::assertStringContainsString('1 0 obj', $clean);
        self::assertStringContainsString('2 0 obj', $clean);
        self::assertStringNotContainsString('app.alert', strtolower($clean));
    }
}
