<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use Exception;
use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Sanitizer\SvgSanitizer;
use SytxLabs\FileSanitizer\Stream\FileChunker;
use SytxLabs\FileSanitizer\Stream\FileWriter;

final class SvgSanitizerTest extends TestCase
{
    private string $tempDir;

    /** @throws Exception */
    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_svg_test_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testSupportsSvgMimeTypeAndExtensionCaseInsensitively(): void
    {
        $sanitizer = new SvgSanitizer();

        self::assertTrue($sanitizer->supports('image/svg+xml', '/tmp/x.dat'));
        self::assertTrue($sanitizer->supports('application/octet-stream', '/tmp/x.SVG'));
        self::assertFalse($sanitizer->supports('text/plain', '/tmp/x.txt'));
    }

    public function testRemovesActiveSvgContentAndMetadata(): void
    {
        [$input, $output] = $this->write('<svg xmlns="http://www.w3.org/2000/svg"><metadata>x</metadata><script>alert(1)</script><image href="https://evil.test/x.png"/><rect onclick="x()" style="background:url(javascript:1)" width="10" height="10"/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);
        $clean = strtolower($this->contents($output));

        self::assertStringNotContainsString('<script', $clean);
        self::assertStringNotContainsString('<metadata', $clean);
        self::assertStringNotContainsString('<image', $clean);
        self::assertStringNotContainsString('onclick=', $clean);
        self::assertStringNotContainsString('javascript:', $clean);
        self::assertStringContainsString('<rect', $clean);
    }

    public function testUsesDefaultStreamAndWriterWhenNoneInjected(): void
    {
        [$input, $output] = $this->write('<svg><rect/></svg>');

        $report = (new SvgSanitizer())->sanitize($input, $output);

        self::assertSame('<svg><rect/></svg>', $this->contents($output));
        self::assertSame($output, $report->outputPath);
    }

    public function testReportIssueCountsRemovedNodesAndMarksMetadataRemoved(): void
    {
        [$input, $output] = $this->write('<svg><script>bad</script><rect/></svg>');

        $report = (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertTrue($report->metadataRemoved);
        self::assertStringContainsString('1 risky or metadata nodes/attributes removed', $report->issues[0]->message);
    }

    public function testReportMarksNoMetadataRemovedWhenNothingWasStripped(): void
    {
        [$input, $output] = $this->write('<svg><rect width="10" height="10"/></svg>');

        $report = (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertFalse($report->metadataRemoved);
        self::assertStringContainsString('0 risky or metadata nodes/attributes removed', $report->issues[0]->message);
    }

    public function testStripsDisallowedElementEvenWithNamespacePrefix(): void
    {
        [$input, $output] = $this->write('<svg><ns:script>bad</ns:script><rect/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringNotContainsString('bad', $clean);
        self::assertStringContainsString('<rect', $clean);
    }

    public function testNestedTagsInsideSkippedSubtreeDoNotPrematurelyEndTheSkip(): void
    {
        [$input, $output] = $this->write('<svg><script><fake></fake>alert(1);</script><rect/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringNotContainsString('script', $clean);
        self::assertStringNotContainsString('fake', $clean);
        self::assertStringNotContainsString('alert', $clean);
        self::assertStringContainsString('<rect', $clean);
    }

    public function testSelfClosingTagInsideSkippedSubtreeDoesNotIncreaseSkipDepth(): void
    {
        [$input, $output] = $this->write('<svg><script><br/></script><rect/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><rect/></svg>', $this->contents($output));
    }

    public function testStrayEndTagWithNothingOnTheStackIsIgnored(): void
    {
        [$input, $output] = $this->write('</foo>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('', $this->contents($output));
    }

    public function testUnterminatedTrailingEndTagAtEofIsDroppedSilently(): void
    {
        [$input, $output] = $this->write('<svg></sv');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testCommentsArePassedThroughInsideAnOpenElement(): void
    {
        [$input, $output] = $this->write('<svg><!-- a comment --></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><!-- a comment --></svg>', $this->contents($output));
    }

    public function testUnterminatedCommentAtEofIsFlushedThenClosedAutomatically(): void
    {
        [$input, $output] = $this->write('<svg><!-- never closes');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><!-- never closes-->', $this->contents($output));
    }

    public function testCdataIsPassedThroughInsideAnOpenElement(): void
    {
        [$input, $output] = $this->write('<svg><![CDATA[<raw> & stuff]]></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><![CDATA[<raw> & stuff]]></svg>', $this->contents($output));
    }

    public function testUnterminatedCdataAtEofIsFlushedThenClosedAutomatically(): void
    {
        [$input, $output] = $this->write('<svg><![CDATA[never closes');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><![CDATA[never closes]]>', $this->contents($output));
    }

    public function testDoctypeDeclarationWithInternalSubsetIsSkippedEntirely(): void
    {
        [$input, $output] = $this->write('<!DOCTYPE svg [ <!ENTITY x "y"> ]><svg><rect/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><rect/></svg>', $this->contents($output));
    }

    public function testUnterminatedDeclarationAtEofConsumesToEndOfBuffer(): void
    {
        [$input, $output] = $this->write('<svg><!DOCTYPE svg');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testProcessingInstructionIsDroppedButSurroundingTextRemains(): void
    {
        [$input, $output] = $this->write('<svg>a<?xml-stylesheet href="x.xsl"?>b</svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>ab</svg>', $this->contents($output));
    }

    public function testUnterminatedProcessingInstructionAtEofIsDroppedSilently(): void
    {
        [$input, $output] = $this->write('<svg><?xml-stylesheet href="x.xsl"');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testLessThanFollowedByInvalidNameCharIsKeptAsLiteralText(): void
    {
        [$input, $output] = $this->write('<svg>1 < 2</svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>1 &lt; 2</svg>', $this->contents($output));
    }

    public function testUnquotedAttributeValuesAreAcceptedAndRequoted(): void
    {
        [$input, $output] = $this->write('<svg><rect width=10 height=20/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><rect width="10" height="20"/></svg>', $this->contents($output));
    }

    public function testStraySlashNotFollowedByGtIsSkippedWhileScanningAttributes(): void
    {
        [$input, $output] = $this->write('<svg><div / data-x="1">content</div></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><div data-x="1">content</div></svg>', $this->contents($output));
    }

    public function testTruncatedAttributeQuoteAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><rect width="10');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedTagNameAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><re');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedTrailingWhitespaceRightAfterTagNameDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><rect ');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedTrailingWhitespaceAfterAttributeNameDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><rect id ');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedTrailingWhitespaceAfterEqualsSignDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><rect width= ');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedUnquotedAttributeValueAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><rect width=10');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testTruncatedLoneSelfClosingSlashAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<svg><div /');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>', $this->contents($output));
    }

    public function testOnAttributeIsAlwaysRemoved(): void
    {
        [$input, $output] = $this->write('<svg><rect onload="evil()" width="1"/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><rect width="1"/></svg>', $this->contents($output));
    }

    /** @return array<int, array{0: string}> */
    public static function urlAttributeProvider(): array
    {
        return [
            'empty value is kept' => ['href=""', true],
            'fragment reference is kept' => ['href="#icon"', true],
            'relative path is kept' => ['href="images/x.png"', true],
            'https scheme is stripped' => ['href="https://evil.test/x"', false],
            'http scheme is stripped' => ['href="http://evil.test/x"', false],
            'javascript scheme is stripped' => ['href="javascript:alert(1)"', false],
            'data scheme is stripped' => ['href="data:text/html,evil"', false],
            'vbscript scheme is stripped' => ['href="vbscript:evil"', false],
            'file scheme is stripped' => ['href="file:///etc/passwd"', false],
        ];
    }

    /** @dataProvider urlAttributeProvider */
    public function testUrlAttributeSchemePolicy(string $attribute, bool $shouldBeKept): void
    {
        [$input, $output] = $this->write('<svg><a ' . $attribute . '>x</a></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertSame($shouldBeKept, str_contains($clean, 'href='));
    }

    /** @return array<int, array{0: string, 1: bool}> */
    public static function styleAttributeProvider(): array
    {
        return [
            'plain style kept' => ['color:red', true],
            'expression() stripped' => ['width:expression(alert(1))', false],
            '@import stripped' => ['@import "evil.css"', false],
            'url() stripped' => ['background:url(evil.png)', false],
            'behavior stripped' => ['behavior:url(evil.htc)', false],
            'moz-binding stripped' => ['-moz-binding:url(evil.xml)', false],
        ];
    }

    /** @dataProvider styleAttributeProvider */
    public function testStyleAttributeDangerousCssPolicy(string $style, bool $shouldBeKept): void
    {
        [$input, $output] = $this->write('<svg><rect style="' . $style . '"/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame($shouldBeKept, str_contains($this->contents($output), 'style='));
    }

    public function testEntitiesInAttributeValuesAreDecodedThenReEscaped(): void
    {
        [$input, $output] = $this->write('<svg><rect data-x="a&amp;b&lt;c"/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg><rect data-x="a&amp;b&lt;c"/></svg>', $this->contents($output));
    }

    public function testEntitiesInTextContentAreDecodedThenReEscaped(): void
    {
        [$input, $output] = $this->write('<svg>a&amp;b&lt;c</svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>a&amp;b&lt;c</svg>', $this->contents($output));
    }

    public function testTinyBufferSplitsATagStartAcrossChunksAndStillParsesCorrectly(): void
    {
        $body = str_repeat('x', 15);
        [$input, $output] = $this->write('<svg>' . $body . '<rect/></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 21]))->sanitize($input, $output);

        self::assertSame('<svg>' . $body . '<rect/></svg>', $this->contents($output));
    }

    public function testTinyBufferSplitsACommentMarkerAcrossChunks(): void
    {
        [$input, $output] = $this->write('<svg><!-- comment text --></svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 7]))->sanitize($input, $output);

        self::assertSame('<svg><!-- comment text --></svg>', $this->contents($output));
    }

    /**
     * The fail-open dump also resets stack/skipDepth to empty, so root context is lost: everything
     * read after the dump is still "text" per the tokenizer but never written, because text is only
     * emitted while an element is open on the stack. So only the bytes carried up to the dump point
     * survive (escaped, as literal text); the remaining garbage is silently discarded, not appended.
     */
    public function testCarryExceedingMaxCarryIsFlushedAsLiteralTextFailOpenThenDropsTheRest(): void
    {
        $garbage = str_repeat('a', 2000);
        [$input, $output] = $this->write('<svg><foo ' . $garbage);

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 16, 'maxCarry' => 50]))->sanitize($input, $output);

        self::assertSame('<svg>&lt;foo ' . str_repeat('a', 54), $this->contents($output));
    }

    public function testLongTextRunExceedingMaxCarryIsFlushedInPiecesWithoutLosingBytes(): void
    {
        $body = str_repeat('B', 5000);
        [$input, $output] = $this->write('<svg>' . $body . '</svg>');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 16, 'maxCarry' => 50]))->sanitize($input, $output);

        self::assertSame('<svg>' . $body . '</svg>', $this->contents($output));
    }

    public function testTrailingLoneLessThanAtTrueEofIsKeptAsLiteralText(): void
    {
        [$input, $output] = $this->write('<svg>text<');

        (new SvgSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<svg>text&lt;', $this->contents($output));
    }

    /** @return array{0: string, 1: string} [inputPath, outputPath] */
    private function write(string $content): array
    {
        $input = $this->tempDir . '/input_' . bin2hex(random_bytes(4)) . '.svg';
        $output = $this->tempDir . '/output_' . bin2hex(random_bytes(4)) . '.svg';
        file_put_contents($input, $content);
        return [$input, $output];
    }

    private function contents(string $path): string
    {
        return (string) file_get_contents($path);
    }
}
