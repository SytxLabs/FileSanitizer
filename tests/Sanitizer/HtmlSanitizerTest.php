<?php

declare(strict_types=1);

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\HtmlSanitizer;

final class HtmlSanitizerTest extends TestCase
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

    /** @noinspection HtmlRequiredAltAttribute
     * @noinspection CssUnknownTarget
     */
    public function testRemovesScriptHandlersDangerousUrlsAndMetaRefresh(): void
    {
        $input = $this->tempDir . '/input.html';
        $output = $this->tempDir . '/output.html';
        file_put_contents($input, '<meta http-equiv="refresh" content="0;url=javascript:alert(1)"><div onclick="x()"><script>alert(1)</script><a href="javascript:alert(1)">bad</a><img src="data:text/html;base64,WA==" style="background:url(javascript:1)">ok</div>');

        (new HtmlSanitizer())->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertStringNotContainsString('<script', strtolower($clean));
        self::assertStringNotContainsString('onclick=', strtolower($clean));
        self::assertStringNotContainsString('http-equiv="refresh"', strtolower($clean));
        self::assertStringNotContainsString('javascript:', strtolower($clean));
        self::assertStringNotContainsString('data:text/html', strtolower($clean));
        self::assertStringNotContainsString('style=', strtolower($clean));
        self::assertStringContainsString('ok', $clean);
    }
}
