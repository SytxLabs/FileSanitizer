<?php

namespace SytxLabs\FileSanitizer\Tests\Dto;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\ScanReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class ScanReportTest extends TestCase
{
    public function testCleanIsSafeWithNoIssues(): void
    {
        $report = ScanReport::clean();

        self::assertTrue($report->safe);
        self::assertSame([], $report->issues);
        self::assertSame('yes', (string) $report);
    }

    public function testUnsafeCarriesGivenIssues(): void
    {
        $issue = new Issue('code', 'message', IssueSeverity::Error);
        $report = ScanReport::unsafe([$issue]);

        self::assertFalse($report->safe);
        self::assertSame([$issue], $report->issues);
        self::assertSame('no', (string) $report);
    }

    public function testToArrayAndJsonSerialize(): void
    {
        $issue = new Issue('code', 'message');
        $report = ScanReport::unsafe([$issue]);

        $expected = ['safe' => false, 'issues' => [$issue]];
        self::assertSame($expected, $report->toArray());
        self::assertSame($expected, $report->jsonSerialize());
    }
}
