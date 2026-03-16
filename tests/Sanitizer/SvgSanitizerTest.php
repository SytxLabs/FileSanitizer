<?php

declare(strict_types=1);

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\SvgSanitizer;

final class SvgSanitizerTest extends TestCase
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

    /** @noinspection CssUnknownTarget */
    public function testRemovesActiveSvgContentAndMetadata(): void
    {
        $input = $this->tempDir . '/input.svg';
        $output = $this->tempDir . '/output.svg';
        file_put_contents($input, '<svg xmlns="http://www.w3.org/2000/svg"><metadata>x</metadata><script>alert(1)</script><image href="https://evil.test/x.png"/><rect onclick="x()" style="background:url(javascript:1)" width="10" height="10"/></svg>');

        (new SvgSanitizer())->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertStringNotContainsString('<script', strtolower($clean));
        self::assertStringNotContainsString('<metadata', strtolower($clean));
        self::assertStringNotContainsString('<image', strtolower($clean));
        self::assertStringNotContainsString('onclick=', strtolower($clean));
        self::assertStringNotContainsString('javascript:', strtolower($clean));
        self::assertStringContainsString('<rect', strtolower($clean));
    }
}
