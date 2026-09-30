<?php

namespace SytxLabs\FileSanitizer\Tests;

use PHPUnit\Framework\TestCase;
use ReflectionMethod;
use SytxLabs\FileSanitizer\FileSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\AudioSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\ImageSanitizer;
use SytxLabs\FileSanitizer\Sanitizer\TextLikeSanitizer;

/**
 * Exercises the defensive early-return guards of private helpers that the public API never
 * reaches with well-formed input, by calling them directly.
 */
final class PrivateGuardsTest extends TestCase
{
    public function testSyncSafeIntReturnsZeroForWrongLength(): void
    {
        self::assertSame(0, $this->call(new AudioSanitizer(), 'syncSafeInt', "\x00\x00\x01"));
        self::assertSame(129, $this->call(new AudioSanitizer(), 'syncSafeInt', "\x00\x00\x01\x01"));
    }

    public function testSplitUtf8SafeReturnsEmptyPairForEmptyChunk(): void
    {
        self::assertSame(['', ''], $this->call(new TextLikeSanitizer(), 'splitUtf8Safe', ''));
    }

    public function testReadFileIfExistsReturnsEmptyStringForMissingFile(): void
    {
        $missing = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fsz_missing_' . bin2hex(random_bytes(6));

        self::assertSame('', $this->call(new FileSanitizer(), 'readFileIfExists', $missing));
    }

    public function testHasMetadataMarkersReturnsFalseForUnreadableFile(): void
    {
        $missing = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'fsz_missing_' . bin2hex(random_bytes(6));

        self::assertFalse($this->call(new ImageSanitizer(), 'hasMetadataMarkers', $missing, IMAGETYPE_JPEG));
    }

    private function call(object $object, string $method, mixed ...$args): mixed
    {
        return (new ReflectionMethod($object, $method))->invoke($object, ...$args);
    }
}
