<?php

namespace SytxLabs\FileSanitizer\Tests\Dto;

use PHPUnit\Framework\TestCase;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class IssueTest extends TestCase
{
    public function testDefaultSeverityIsWarning(): void
    {
        $issue = new Issue('code', 'message');

        self::assertSame(IssueSeverity::Warning, $issue->severity);
    }

    public function testToStringFormatsSeverityCodeAndMessage(): void
    {
        $issue = new Issue('svg_cleaned', 'stripped script tag', IssueSeverity::Error);

        self::assertSame('[error] svg_cleaned: stripped script tag', (string) $issue);
    }

    public function testToArrayExposesPlainScalars(): void
    {
        $issue = new Issue('code', 'message', IssueSeverity::Info);

        self::assertSame([
            'code' => 'code',
            'message' => 'message',
            'severity' => 'info',
        ], $issue->toArray());
    }

    public function testJsonSerializeMatchesToArray(): void
    {
        $issue = new Issue('code', 'message', IssueSeverity::Info);

        self::assertSame($issue->toArray(), $issue->jsonSerialize());
        self::assertSame('{"code":"code","message":"message","severity":"info"}', json_encode($issue));
    }
}
