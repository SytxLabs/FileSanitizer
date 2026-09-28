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

    public function testSupportsOnlyHtmlMimeTypes(): void
    {
        $sanitizer = new HtmlSanitizer();

        self::assertTrue($sanitizer->supports('text/html', '/tmp/x.dat'));
        self::assertTrue($sanitizer->supports('application/xhtml+xml', '/tmp/x.dat'));
        self::assertFalse($sanitizer->supports('text/plain', '/tmp/x.html'));
    }

    public function testUsesDefaultStreamAndWriterWhenNoneInjected(): void
    {
        $input = $this->tempDir . '/default.html';
        $output = $this->tempDir . '/default.out.html';
        file_put_contents($input, '<p>hi</p>');

        $report = (new HtmlSanitizer())->sanitize($input, $output);

        self::assertSame('<p>hi</p>', (string) file_get_contents($output));
        self::assertSame($output, $report->outputPath);
    }

    public function testTopLevelTextOutsideAnyElementIsStillWritten(): void
    {
        [$input, $output] = $this->write('before<p>mid</p>after');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('before<p>mid</p>after', $this->contents($output));
    }

    public function testDoctypeDeclarationIsDroppedButSurroundingContentRemains(): void
    {
        [$input, $output] = $this->write('<!DOCTYPE html><p>ok</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testUnterminatedDeclarationAtEofIsDroppedSilently(): void
    {
        [$input, $output] = $this->write('<p>ok</p><!DOCTYPE html');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testUnterminatedCommentAtEofIsClosedAutomatically(): void
    {
        [$input, $output] = $this->write('<p>ok</p><!-- never closes');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p><!-- never closes-->', $this->contents($output));
    }

    public function testVoidElementIsNotPushedOntoTheStack(): void
    {
        [$input, $output] = $this->write('<p>before<br>after</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>before<br>after</p>', $this->contents($output));
    }

    public function testStrayEndTagWithNoMatchingOpenElementIsIgnored(): void
    {
        [$input, $output] = $this->write('<p>ok</div></p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testAnchorWithoutHrefIsNotGivenARelAttribute(): void
    {
        [$input, $output] = $this->write('<a>no href here</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<a>no href here</a>', $this->contents($output));
    }

    public function testAnchorWithHrefAndNoExistingRelGetsSafeRelAdded(): void
    {
        [$input, $output] = $this->write('<a href="https://x.test">go</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<a href="https://x.test" rel="nofollow noopener noreferrer">go</a>', $this->contents($output));
    }

    public function testDisallowedAttributeOnAllowedTagIsRemoved(): void
    {
        [$input, $output] = $this->write('<div data-evil="x">ok</div>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<div>ok</div>', $this->contents($output));
    }

    public function testGlobalAttributeIsKeptOnAnyAllowedTag(): void
    {
        [$input, $output] = $this->write('<div class="box" id="a" title="t" lang="en" dir="ltr" aria-label="l" aria-hidden="true" role="note">ok</div>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringContainsString('class="box"', $clean);
        self::assertStringContainsString('role="note"', $clean);
    }

    public function testImgAllowsWidthAndHeightAttributes(): void
    {
        [$input, $output] = $this->write('<img src="/x.png" alt="a" width="10" height="20">');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<img src="/x.png" alt="a" width="10" height="20">', $this->contents($output));
    }

    public function testTableCellAllowsColspanRowspanAndScope(): void
    {
        [$input, $output] = $this->write('<table><tr><th colspan="2" rowspan="1" scope="col">h</th></tr></table>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertStringContainsString('colspan="2" rowspan="1" scope="col"', $this->contents($output));
    }

    public function testMetaAllowsCharsetNameAndContent(): void
    {
        [$input, $output] = $this->write('<meta charset="utf-8" name="description" content="x">');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<meta charset="utf-8" name="description" content="x">', $this->contents($output));
    }

    public function testImageDataUriIsAllowedOnlyForImgSrc(): void
    {
        [$input, $output] = $this->write('<img src="data:image/png;base64,QQ==">');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertStringContainsString('data:image/png;base64,QQ==', $this->contents($output));
    }

    public function testFragmentAndRootRelativeUrlsAreKept(): void
    {
        [$input, $output] = $this->write('<a href="#section">s</a><a href="/path">p</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringContainsString('href="#section"', $clean);
        self::assertStringContainsString('href="/path"', $clean);
    }

    public function testMailtoAndTelUrlsAreKept(): void
    {
        [$input, $output] = $this->write('<a href="mailto:x@example.test">m</a><a href="tel:+123">t</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringContainsString('mailto:x@example.test', $clean);
        self::assertStringContainsString('tel:+123', $clean);
    }

    public function testUnrecognizedUrlSchemeIsKeptSinceItIsNotOnTheBlockList(): void
    {
        [$input, $output] = $this->write('<a href="ftp://x.test/file">f</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertStringContainsString('ftp://x.test/file', $this->contents($output));
    }

    public function testDataUriIsBlockedOnNonImageUrlAttribute(): void
    {
        [$input, $output] = $this->write('<a href="data:text/html,evil">d</a>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertStringNotContainsString('href=', $this->contents($output));
    }

    public function testStyleAttributeStripsControlCharactersAndTrims(): void
    {
        [$input, $output] = $this->write("<div style=\" color:red;\x07 \">ok</div>");

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<div style="color:red;">ok</div>', $this->contents($output));
    }

    /**
     * The disallowed <script> start tag itself is stripped, but per
     * testPreservesLookalikeEndTagInsideRawtextAsEscapedText its rawtext content still flows
     * through as escaped text (HTML's flushText, unlike SVG's, has no open-stack guard). A "</scriptx"
     * lookalike is not a boundary-terminated end tag, so the scan continues past it to the real one.
     */
    public function testAmbiguousRawTextEndTagLookalikeIsNotTreatedAsRealEndTag(): void
    {
        [$input, $output] = $this->write('<script>a<' . '/scriptx more</script><p>ok</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('a&lt;/scriptx more<p>ok</p>', $this->contents($output));
    }

    public function testRawTextEndNeedleSplitExactlyAtChunkBoundaryIsStillFound(): void
    {
        $html = '<script>' . str_repeat('x', 10) . '</script><p>ok</p>';
        [$input, $output] = $this->write($html);

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 18]))->sanitize($input, $output);

        self::assertSame(str_repeat('x', 10) . '<p>ok</p>', $this->contents($output));
    }

    public function testCarryExceedingMaxCarryIsFlushedAsLiteralTextWithoutLosingContent(): void
    {
        $garbage = str_repeat('a', 2000);
        [$input, $output] = $this->write('<foo ' . $garbage . '><p>ok</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 16, 'maxCarry' => 50]))->sanitize($input, $output);

        $clean = $this->contents($output);
        self::assertStringContainsString('&lt;foo ', $clean);
        self::assertStringContainsString($garbage, $clean);
    }

    public function testLongTextRunExceedingMaxCarryIsFlushedInPiecesWithoutLosingBytes(): void
    {
        $body = str_repeat('B', 5000);
        [$input, $output] = $this->write('<p>' . $body . '</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 16, 'maxCarry' => 50]))->sanitize($input, $output);

        self::assertSame('<p>' . $body . '</p>', $this->contents($output));
    }

    public function testTruncatedTagNameAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p><di');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testTruncatedEndTagNameAtEofDropsTheIncompleteEndTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p></di');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testTruncatedEndTagMissingGtAtEofDropsTheIncompleteEndTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p></div ');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testNormalCommentIsPassedThroughVerbatim(): void
    {
        [$input, $output] = $this->write('<p>ok</p><!-- a comment --><p>more</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p><!-- a comment --><p>more</p>', $this->contents($output));
    }

    public function testTinyBufferSplitsMarkupDeclarationMarkerAcrossChunks(): void
    {
        [$input, $output] = $this->write('<p>ok</p><!DOCTYPE html><p>more</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output), ['bufferSize' => 11]))->sanitize($input, $output);

        self::assertSame('<p>ok</p><p>more</p>', $this->contents($output));
    }

    public function testSelfClosingSlashSyntaxIsAccepted(): void
    {
        [$input, $output] = $this->write('<p>before<br/>after</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>before<br>after</p>', $this->contents($output));
    }

    public function testTruncatedLoneSelfClosingSlashAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p><div /');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testTruncatedTrailingWhitespaceAfterAttributeNameDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p><div id ');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testTruncatedTrailingWhitespaceAfterEqualsSignDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p><div id= ');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testTrailingLoneLessThanAtTrueEofIsKeptAsLiteralText(): void
    {
        [$input, $output] = $this->write('<p>ok</p>text<');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>text&lt;', $this->contents($output));
    }

    public function testLessThanFollowedByInvalidNameCharIsKeptAsLiteralText(): void
    {
        [$input, $output] = $this->write('<p>1 < 2</p>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>1 &lt; 2</p>', $this->contents($output));
    }

    public function testRawTextThatNeverClosesAtEofIsFlushedAsEscapedText(): void
    {
        [$input, $output] = $this->write('<script>abc');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('abc', $this->contents($output));
    }

    public function testUnquotedAttributeValuesAreAcceptedAndRequoted(): void
    {
        [$input, $output] = $this->write('<div id=abc>ok</div>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<div id="abc">ok</div>', $this->contents($output));
    }

    public function testStraySlashNotFollowedByGtIsSkippedWhileScanningAttributes(): void
    {
        [$input, $output] = $this->write('<div / id="abc">ok</div>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<div id="abc">ok</div>', $this->contents($output));
    }

    public function testTruncatedAttributeQuoteAtEofDropsTheIncompleteTag(): void
    {
        [$input, $output] = $this->write('<p>ok</p><div id="abc');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<p>ok</p>', $this->contents($output));
    }

    public function testEntitiesInAttributeValuesAndTextAreDecodedThenReEscaped(): void
    {
        [$input, $output] = $this->write('<div title="a&amp;b">x&lt;y</div>');

        (new HtmlSanitizer(new FileChunker($input), new FileWriter($output)))->sanitize($input, $output);

        self::assertSame('<div title="a&amp;b">x&lt;y</div>', $this->contents($output));
    }

    /** @return array{0: string, 1: string} [inputPath, outputPath] */
    private function write(string $content): array
    {
        $input = $this->tempDir . '/input_' . bin2hex(random_bytes(4)) . '.html';
        $output = $this->tempDir . '/output_' . bin2hex(random_bytes(4)) . '.html';
        file_put_contents($input, $content);
        return [$input, $output];
    }

    private function contents(string $path): string
    {
        return (string) file_get_contents($path);
    }
}
