<?php

namespace SytxLabs\FileSanitizer\Tests\Sanitizer;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\FileSanitizer;

final class FileSanitizerInputStringTest extends TestCase
{
    public function testProcessStringSanitizesHtmlPayloadAndReturnsSanitizedData(): void
    {
        $sanitizer = new FileSanitizer();
        $result = $sanitizer->processString('<div onclick="x()"><script>alert(1)</script>ok</div>', 'upload.html', true);

        self::assertArrayHasKey('sanitizedData', $result);
        self::assertStringNotContainsString('<script', strtolower($result['sanitizedData']));
        self::assertStringNotContainsString('onclick=', strtolower($result['sanitizedData']));
        self::assertStringContainsString('ok', $result['sanitizedData']);
    }

    public function testProcessBase64SanitizesDataUriAndReturnsSanitizedBase64(): void
    {
        $sanitizer = new FileSanitizer();
        $payload = 'data:image/svg+xml;base64,' . base64_encode('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script><circle cx="5" cy="5" r="5"/></svg>');

        $result = $sanitizer->processBase64($payload, 'upload.svg', true);

        self::assertArrayHasKey('sanitizedData', $result);
        self::assertArrayHasKey('sanitizedBase64', $result);
        self::assertStringNotContainsString('<script', strtolower($result['sanitizedData']));
        self::assertSame($result['sanitizedData'], base64_decode($result['sanitizedBase64'], true));
    }

    public function testProcessStringDetectsMimeTypeFromDataWhenHintIsNull(): void
    {
        $sanitizer = new FileSanitizer();
        $payload = '<!doctype html><div onclick="x()"><script>alert(1)</script>safe</div>';

        $result = $sanitizer->processString($payload, null, true);

        self::assertSame('text/html', $result['mimeType']);
        self::assertStringNotContainsString('<script', strtolower($result['sanitizedData']));
        self::assertStringNotContainsString('onclick=', strtolower($result['sanitizedData']));
        self::assertStringContainsString('safe', $result['sanitizedData']);
    }

    public function testProcessStringSupportsPythonStyleBytesLiteralBlob(): void
    {
        $sanitizer = new FileSanitizer();
        $blobLiteral = 'b"<!doctype html><div onclick=\\"x()\\"><script>alert(1)</script>blob</div>"';

        $result = $sanitizer->processString($blobLiteral, null, true);

        self::assertSame('text/html', $result['mimeType']);
        self::assertStringNotContainsString('<script', strtolower($result['sanitizedData']));
        self::assertStringNotContainsString('onclick=', strtolower($result['sanitizedData']));
        self::assertStringContainsString('blob', $result['sanitizedData']);
    }

    public function testProcessBinarySupportsRawImageBytes(): void
    {
        $sanitizer = new FileSanitizer();
        $image = imagecreatetruecolor(1, 1);
        self::assertNotFalse($image);
        ob_start();
        imagepng($image);
        imagedestroy($image);
        $pngBytes = ob_get_clean();
        self::assertIsString($pngBytes);

        $result = $sanitizer->processBinary($pngBytes, null, true, true, 'image/png');

        self::assertSame('image/png', $result['mimeType']);
        self::assertNotSame('', $result['sanitizedData']);
        self::assertSame("\x89PNG\r\n\x1A\n", substr($result['sanitizedData'], 0, 8));
    }
}
