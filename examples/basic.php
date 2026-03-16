<?php

require __DIR__ . '/../vendor/autoload.php';

use SytxLabs\FileSanitizer\FileSanitizer;

$input = $argv[1] ?? null;

if ($input === null) {
    fwrite(STDERR, "Usage: php examples/basic.php /path/to/file\n");
    exit(1);
}

$sanitizer = new FileSanitizer();
$result = $sanitizer->process($input);

printf("MIME: %s\n", $result['mimeType']);
printf("Scan safe: %s\n", $result['scan']->safe ? 'yes' : 'no');
printf("Output: %s\n", $result['sanitize']->outputPath);

foreach ($result['sanitize']->issues as $issue) {
    printf("- [%s] %s: %s\n", strtoupper($issue->severity), $issue->code, $issue->message);
}
