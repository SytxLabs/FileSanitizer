<?php

namespace SytxLabs\FileSanitizer\Tests\MimeDetector;

use PHPUnit\Framework\TestCase;
use RuntimeException;
use SytxLabs\FileSanitizer\MimeDetector\MimeDetector;

final class MimeDetectorTest extends TestCase
{
    private string $path;

    protected function setUp(): void
    {
        $this->path = tempnam(sys_get_temp_dir(), 'fsz_mime_');
    }

    protected function tearDown(): void
    {
        @unlink($this->path);
    }

    public function testDetectsAndNormalizesMimeTypeOfTextFile(): void
    {
        file_put_contents($this->path, "plain text content\n");

        $mimeType = (new MimeDetector())->detect($this->path);

        self::assertSame('text/plain', $mimeType);
        self::assertSame(strtolower($mimeType), $mimeType);
    }

    /**
     * finfo_file() emits a PHP warning (not just a false return) for a stream it cannot open, so the
     * failing call must be suppressed here the same way a caller running outside PHPUnit's strict
     * warning-to-exception handler would experience it, in order to reach detect()'s own
     * false-result guard rather than PHPUnit's warning-to-error conversion.
     */
    public function testThrowsRuntimeExceptionWhenPathCannotBeOpened(): void
    {
        $missing = $this->path . '_missing';
        $this->expectException(RuntimeException::class);

        $detector = new MimeDetector();
        @$detector->detect($missing);
    }
}
