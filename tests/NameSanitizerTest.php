<?php

namespace SytxLabs\FileSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Contracts\NameSanitizerInterface;
use SytxLabs\FileSanitizer\NameSanitizer;

final class NameSanitizerTest extends TestCase
{
    private NameSanitizerInterface $sanitizer;

    protected function setUp(): void
    {
        $this->sanitizer = new NameSanitizer();
    }

    public function testPassesThroughAnAlreadySafeName(): void
    {
        self::assertSame('report.pdf', $this->sanitizer->sanitize('report.pdf'));
    }

    public function testStripsPathTraversalAndDirectoryComponents(): void
    {
        self::assertSame('passwd', $this->sanitizer->sanitize('../../etc/passwd'));
        self::assertSame('passwd', $this->sanitizer->sanitize('/etc/passwd'));
        self::assertSame('file.txt', $this->sanitizer->sanitize('C:\\Windows\\file.txt'));
        // Windows-style traversal fed through on a Linux/macOS host: native basename() would leave
        // this untouched since '\' isn't a separator there, so it must be normalized first.
        self::assertSame('passwd', $this->sanitizer->sanitize('..\\..\\etc\\passwd'));
        self::assertSame('passwd', $this->sanitizer->sanitize('../..\\etc/passwd'));
    }

    public function testCollapsesBareTraversalMarkers(): void
    {
        // A name that is nothing but traversal dots has nothing left after boundary-trimming, so
        // it falls back to the default name rather than producing an odd "__".
        self::assertSame('file', $this->sanitizer->sanitize('..'));
        self::assertSame('foo__bar', $this->sanitizer->sanitize('foo..bar'));
    }

    public function testReplacesNullBytesAndControlCharacters(): void
    {
        self::assertSame('evil_.txt', $this->sanitizer->sanitize("evil\x00.txt"));
        self::assertSame('fi_le.txt', $this->sanitizer->sanitize("fi\x01le.txt"));
    }

    public function testReplacesReservedFilesystemCharacters(): void
    {
        self::assertSame('a_b_c_d_e_f_g.txt', $this->sanitizer->sanitize('a<b>c:d"e|f?g.txt'));
    }

    public function testStripsUnicodeSpoofingAndShellMetacharacters(): void
    {
        // An allow-list (only ASCII letters/digits/space/._-()) catches what a fixed blacklist of
        // Windows-reserved characters would miss: a right-to-left override used to make
        // "invoice\u{202E}gnp.exe" display as "invoice.png" reversed, and shell metacharacters that
        // are legal filename bytes on every OS but dangerous if the name is ever interpolated
        // unescaped into a command.
        self::assertSame('invoice_gnp.exe', $this->sanitizer->sanitize("invoice\u{202E}gnp.exe"));
        self::assertSame('a_b_c_d.txt', $this->sanitizer->sanitize('a`b;c$d.txt'));
    }

    public function testReplacesColonReservedOnMacOs(): void
    {
        // ':' was the classic Mac OS path separator and is still rejected by some macOS APIs; '/'
        // is the one byte forbidden outright on Linux (ext4) and is covered by the same rule.
        self::assertSame('report_2024.pdf', $this->sanitizer->sanitize('report:2024.pdf'));
    }

    public function testTrimsTrailingDotsAndSpaces(): void
    {
        self::assertSame('file.txt', $this->sanitizer->sanitize('file.txt   ...'));
    }

    public function testFallsBackToDefaultNameWhenNothingSurvives(): void
    {
        self::assertSame('file', $this->sanitizer->sanitize(''));
        self::assertSame('file', $this->sanitizer->sanitize('.'));
        self::assertSame('file', $this->sanitizer->sanitize('   '));
    }

    public function testGuardsReservedWindowsDeviceNames(): void
    {
        self::assertSame('_CON', $this->sanitizer->sanitize('CON'));
        self::assertSame('_con.txt', $this->sanitizer->sanitize('con.txt'));
        self::assertSame('_LPT1', $this->sanitizer->sanitize('LPT1'));
    }

    public function testTruncatesOverlongNamesWhilePreservingExtension(): void
    {
        $result = $this->sanitizer->sanitize(str_repeat('a', 300) . '.txt');

        self::assertSame(255, strlen($result));
        self::assertStringEndsWith('.txt', $result);
    }

    public function testCustomReplacementCharacterIsUsed(): void
    {
        self::assertSame('a-b-c.txt', $this->sanitizer->sanitize('a:b?c.txt', '-'));
    }
}
