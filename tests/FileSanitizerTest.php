<?php

namespace SytxLabs\FileSanitizer\Tests;

use Exception;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Contracts\ScannerInterface;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;
use SytxLabs\FileSanitizer\FileSanitizer;
use SytxLabs\FileSanitizer\MimeDetector\MimeDetector;

final class FileSanitizerTest extends TestCase
{
    private string $tempDir;

    /** @throws Exception */
    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/fsz_fs_test_' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);
    }

    protected function tearDown(): void
    {
        foreach (glob($this->tempDir . '/*') ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->tempDir);
    }

    public function testMarksUnchangedAndAddsInfoIssueWhenScanCleanAndSanitizerMadeNoChanges(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'hello world');
        $output = $this->tempDir . '/output.txt';

        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner(ScanReport::clean()),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: true)]
        );

        $result = $fileSanitizer->process($input, $output);

        self::assertTrue($result['sanitize']->unchanged);
        $codes = array_map(static fn (Issue $issue) => $issue->code, $result['sanitize']->issues);
        self::assertContains('sanitizer_no_changes', $codes);
    }

    /**
     * $unchanged is a plain fact about the sanitize step alone, so it stays true even when the scan
     * found issues (the sanitizer here really did leave the file byte-identical). What must NOT
     * happen is the reassuring "no changes were necessary" Issue: that would misrepresent an
     * unresolved threat as a safe outcome. A caller determines real safety by checking
     * $scan->safe together with $sanitize->unchanged, never $sanitize->unchanged alone.
     */
    public function testReportsUnchangedButWithoutTheSafeIssueWhenScanFoundIssues(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'dangerous content');
        $output = $this->tempDir . '/output.txt';

        $unsafeScan = ScanReport::unsafe([new Issue('danger', 'found something bad', IssueSeverity::Error)]);
        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner($unsafeScan),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: true)]
        );

        $result = $fileSanitizer->process($input, $output, true);

        self::assertTrue($result['sanitize']->unchanged);
        $codes = array_map(static fn (Issue $issue) => $issue->code, $result['sanitize']->issues);
        self::assertNotContains('sanitizer_no_changes', $codes);
    }

    public function testUnchangedIsFalseWhenSanitizerActuallyChangedTheFile(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'hello world');
        $output = $this->tempDir . '/output.txt';

        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner(ScanReport::clean()),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: false)]
        );

        $result = $fileSanitizer->process($input, $output);

        self::assertFalse($result['sanitize']->unchanged);
    }

    /**
     * process() previously called ->detect() directly on the constructor-supplied mimeDetector
     * without going through buildInterface() (the helper scan() already used), so a class-string
     * mimeDetector — a form the constructor's own type signature explicitly allows — crashed with
     * "Call to a member function detect() on string" instead of being instantiated.
     */
    public function testProcessAcceptsAMimeDetectorGivenAsAClassString(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'hello world');

        $fileSanitizer = new FileSanitizer(mimeDetector: MimeDetector::class);

        $result = $fileSanitizer->process($input);

        self::assertSame('text/plain', $result['mimeType']);
    }

    public function testScanThrowsWhenFileDoesNotExist(): void
    {
        $fileSanitizer = new FileSanitizer();

        $this->expectException(Exception::class);
        $fileSanitizer->scan($this->tempDir . '/does-not-exist.txt');
    }

    public function testProcessThrowsWhenFileDoesNotExist(): void
    {
        $fileSanitizer = new FileSanitizer();

        $this->expectException(Exception::class);
        $fileSanitizer->process($this->tempDir . '/does-not-exist.txt');
    }

    public function testBooleanSecondArgumentIsTreatedAsSanitizeAlwaysShorthand(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'dangerous content');

        $unsafeScan = ScanReport::unsafe([new Issue('danger', 'found something bad', IssueSeverity::Error)]);
        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner($unsafeScan),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: true)]
        );

        // Passing `true` as the second positional argument is shorthand for sanitizeAlways=true
        // with a default output path (derived from the input path, not passed explicitly here).
        $result = $fileSanitizer->process($input, true);

        self::assertFileExists($result['sanitize']->outputPath);
        self::assertNotSame(['skipped' => true], $result['sanitize']->context);
    }

    public function testUnsafeScanWithoutSanitizeAlwaysSkipsSanitizationAndReturnsScanIssues(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'dangerous content');
        $output = $this->tempDir . '/output.txt';

        $unsafeScan = ScanReport::unsafe([new Issue('danger', 'found something bad', IssueSeverity::Error)]);
        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner($unsafeScan),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: true)]
        );

        $result = $fileSanitizer->process($input, $output);

        self::assertFalse($result['sanitize']->unchanged);
        self::assertSame($unsafeScan->issues, $result['sanitize']->issues);
        self::assertSame(['skipped' => true], $result['sanitize']->context);
        self::assertFileDoesNotExist($output);
    }

    public function testSanitizeAlwaysConvenienceMethodForcesSanitization(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'dangerous content');
        $output = $this->tempDir . '/output.txt';

        $unsafeScan = ScanReport::unsafe([new Issue('danger', 'found something bad', IssueSeverity::Error)]);
        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner($unsafeScan),
            sanitizerCandidates: [$this->fakeSanitizer(copyUnchanged: true)]
        );

        $result = $fileSanitizer->sanitizeAlways($input, $output);

        self::assertFileExists($output);
        self::assertNotSame(['skipped' => true], $result['sanitize']->context);
    }

    /**
     * A pre-instantiated candidate whose supports() returns false must be skipped in favor of a
     * later candidate, exactly like a class-string candidate would be — this exercises that skip
     * path specifically for the already-instantiated-object branch of resolveSanitizer().
     */
    public function testResolveSanitizerSkipsAPreInstantiatedCandidateThatDoesNotSupportTheMimeType(): void
    {
        $input = $this->tempDir . '/input.txt';
        file_put_contents($input, 'hello world');
        $output = $this->tempDir . '/output.txt';

        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner(ScanReport::clean()),
            sanitizerCandidates: [
                $this->fakeSanitizer(copyUnchanged: false, supports: false),
                $this->fakeSanitizer(copyUnchanged: true, supports: true),
            ]
        );

        $result = $fileSanitizer->process($input, $output);

        self::assertFileExists($output);
        self::assertTrue($result['sanitize']->unchanged);
    }

    /**
     * copy() emits a PHP warning (not just a false return) when the destination directory does
     * not exist. It is suppressed here the same way it would be outside PHPUnit's strict
     * warning-to-exception handler, so process()'s own failure guard is what's under test.
     */
    public function testThrowsWhenCopyingUnsupportedFileToOutputPathFails(): void
    {
        $input = $this->tempDir . '/input.unknown';
        file_put_contents($input, 'unrecognized content');
        $output = $this->tempDir . '/missing-dir/output.unknown';

        $fileSanitizer = new FileSanitizer(
            scanner: $this->fakeScanner(ScanReport::clean()),
            sanitizerCandidates: []
        );

        $this->expectException(RuntimeException::class);
        @$fileSanitizer->process($input, $output);
    }

    /**
     * The constructor signature here must stay compatible with ScannerInterface's own — unlike
     * class inheritance, PHP enforces LSP-compatible __construct() signatures when implementing an
     * interface that declares one, so the fixture data is injected via a public property set right
     * after construction instead of through custom constructor parameters.
     */
    private function fakeScanner(ScanReport $report): ScannerInterface
    {
        $scanner = new class implements ScannerInterface
        {
            public ScanReport $report;

            public function __construct(?StreamInterface $stream = null, ?array $options = null)
            {
            }

            public function supports(string $mimeType, string $path): bool
            {
                return true;
            }

            public function scan(string $path, string $mimeType): ScanReport
            {
                return $this->report;
            }
        };
        $scanner->report = $report;
        return $scanner;
    }

    private function fakeSanitizer(bool $copyUnchanged, bool $supports = true): SanitizerInterface
    {
        $sanitizer = new class implements SanitizerInterface
        {
            public bool $copyUnchanged;

            public bool $supportsFlag;

            public function __construct(?StreamInterface $stream = null, ?OutputInterface $output = null, ?array $options = null)
            {
            }

            public function supports(string $mimeType, string $path): bool
            {
                return $this->supportsFlag;
            }

            public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
            {
                if ($this->copyUnchanged) {
                    copy($inputPath, $outputPath);
                } else {
                    file_put_contents($outputPath, 'different content');
                }
                return new SanitizeReport($outputPath, false, []);
            }
        };
        $sanitizer->copyUnchanged = $copyUnchanged;
        $sanitizer->supportsFlag = $supports;
        return $sanitizer;
    }
}
