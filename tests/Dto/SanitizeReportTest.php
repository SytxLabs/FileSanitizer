<?php

namespace SytxLabs\FileSanitizer\Tests\Dto;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;

final class SanitizeReportTest extends TestCase
{
    public function testDefaultsForOptionalFields(): void
    {
        $report = new SanitizeReport('/tmp/out.txt', false);

        self::assertSame('/tmp/out.txt', $report->outputPath);
        self::assertFalse($report->metadataRemoved);
        self::assertSame([], $report->issues);
        self::assertSame([], $report->context);
        self::assertFalse($report->unchanged);
        self::assertSame('/tmp/out.txt', (string) $report);
    }

    public function testToArrayAndJsonSerializeIncludeAllFields(): void
    {
        $issue = new Issue('code', 'message');
        $report = new SanitizeReport('/tmp/out.txt', true, [$issue], ['sanitized_despite_scan_issues' => true], true);

        $expected = [
            'outputPath' => '/tmp/out.txt',
            'metadataRemoved' => true,
            'issues' => [$issue],
            'context' => ['sanitized_despite_scan_issues' => true],
            'unchanged' => true,
        ];

        self::assertSame($expected, $report->toArray());
        self::assertSame($expected, $report->jsonSerialize());
    }
}
