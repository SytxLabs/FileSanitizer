<?php

require __DIR__ . '/../vendor/autoload.php';

use SytxLabs\FileSanitizer\FileSanitizer;

$files = [];
echo '<ul>';
foreach (glob(__DIR__ . '/../files/*') as $file) {
    $files[] = $file;
    echo '<li><a href="?file=' . $file . '">' . $file . '</a></li>';
}
echo '</ul>';
$file = $_GET['file'] ?? null;
if (!$file) {
    return;
}

$sanitizer = new FileSanitizer();
$outputPath = $file . '.sanitized.' . pathinfo($file, PATHINFO_EXTENSION);
$result = $sanitizer->process($file, $outputPath, true);

echo '<pre>';
print_r($result);
echo '</pre>';
