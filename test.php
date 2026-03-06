<?php

require __DIR__ . '/vendor/autoload.php';

use SytxLabs\FileSanitizer\FileSanitizer;

$sanitizer = new FileSanitizer();

$result = $sanitizer->sanitize(
    __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'xssPDF-1.pdf',
    __DIR__ . DIRECTORY_SEPARATOR . 'files' . DIRECTORY_SEPARATOR . 'xssPDF-1.clean.pdf',
);

print_r($result->toArray());
