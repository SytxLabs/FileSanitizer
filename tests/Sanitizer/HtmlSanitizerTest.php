<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\HtmlSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class HtmlSanitizerTest extends TestCase
{
    private string $tempDir;

    /** @throws Exception */
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

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertStringNotContainsString('<script', strtolower($clean));
        self::assertStringNotContainsString('onclick=', strtolower($clean));
        self::assertStringNotContainsString('http-equiv="refresh"', strtolower($clean));
        self::assertStringNotContainsString('javascript:', strtolower($clean));
        self::assertStringNotContainsString('data:text/html', strtolower($clean));
        self::assertStringNotContainsString('style=', strtolower($clean));
        self::assertStringContainsString('ok', $clean);
    }

    public function testProducesIdenticalOutputRegardlessOfBufferSize(): void
    {
        $html = '<div onclick="x()">before<script>if (a<b) { var s = "</style><img src=x onerror=alert(1)>"; }</script><a href="javascript:alert(1)" rel="evil">bad</a><a href="https://x.test" rel="me">good</a><font color=red>outer<font color=blue>inner</font>after</font>ok</div>';

        $input = $this->tempDir . '/chunked.html';
        file_put_contents($input, $html);

        $reference = $this->tempDir . '/chunked.ref.html';
        (new HtmlSanitizer(new FileChunker($input), new FileWriter($reference)))->sanitize($input, $reference);
        $referenceOutput = (string) file_get_contents($reference);

        foreach ([1, 3, 7] as $bufferSize) {
            $output = $this->tempDir . '/chunked.' . $bufferSize . '.html';
            (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => $bufferSize]))->sanitize($input, $output);
            self::assertSame($referenceOutput, (string) file_get_contents($output), "Output differs at bufferSize=$bufferSize");
        }
    }

    public function testPreservesLookalikeEndTagInsideRawtextAsEscapedText(): void
    {
        $input = $this->tempDir . '/rawtext.html';
        $output = $this->tempDir . '/rawtext.out.html';
        file_put_contents($input, '<style>.a{}</style-not-real>.b{}</style><p>ok</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertStringNotContainsString('<style', $clean);
        self::assertStringContainsString('&lt;/style-not-real&gt;', $clean);
        self::assertStringContainsString('<p>ok</p>', $clean);
    }

    public function testUnwrapsNestedDisallowedTagsOfTheSameName(): void
    {
        $input = $this->tempDir . '/nested.html';
        $output = $this->tempDir . '/nested.out.html';
        file_put_contents($input, '<font color=red>outer<font color=blue>inner</font>after</font>done');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
        $clean = (string) file_get_contents($output);

        self::assertSame('outerinnerafterdone', $clean);
    }

    public function testReportsMetadataRemovedOnlyWhenSomethingWasActuallyStripped(): void
    {
        $input = $this->tempDir . '/clean.html';
        $output = $this->tempDir . '/clean.out.html';
        file_put_contents($input, '<p>already safe</p>');

        $report = (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFalse($report->metadataRemoved);
    }
}
