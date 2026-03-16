# FileSanitizer

Pure PHP file sanitizer and scanner for uploaded files. It strips metadata where practical, rewrites selected file types into safer forms, and blocks files that look malicious.

## Features

- Re-encodes JPEG, PNG, GIF, and WebP images to strip EXIF and ancillary metadata
- Scans HTML, SVG, PDF, text, Office OOXML, ZIP, and nested ZIP content for risky payloads
- Recursively scans ZIP archives with depth, entry-count, and expanded-size guards
- Detects common XSS-style payloads such as `<script>`, inline handlers, `javascript:` URLs, hostile CSS, and dangerous PDF actions
- Applies strict allowlist-based cleanup for HTML and strict removal rules for SVG
- Does not use SSH, shell commands, or `setasign/fpdf`

## Install

```bash
composer require filesanitizer/filesanitizer
```

For development and tests:

```bash
composer install
composer test
```

PHPUnit is added as a dev dependency. PHPUnit 13 is currently the stable release, while PHPUnit 11 requires PHP 8.2+ and PHPUnit 12 requires PHP 8.3+. This package keeps a flexible dev constraint so Composer can resolve a compatible PHPUnit version for your PHP runtime. citeturn204189search3turn204189search6turn204189search12

## Usage

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use FileSanitizer\FileSanitizer;

$sanitizer = new FileSanitizer();
$result = $sanitizer->process(__DIR__ . '/upload.svg');

if (!$result['scan']->safe) {
    foreach ($result['scan']->issues as $issue) {
        echo $issue->code . ': ' . $issue->message . PHP_EOL;
    }
    exit(1);
}

echo 'Sanitized file written to: ' . $result['sanitize']->outputPath . PHP_EOL;
```

## Archive scanning notes

The recursive archive scanner uses PHP's `ZipArchive` extension and does not extract archives to a shell. PHP documents `ZipArchive` for reading archive entries and notes extraction and open behavior through the zip extension API. citeturn204189search1turn204189search4turn204189search16

Current guards:

- Maximum nesting depth: 3
- Maximum scanned entries per archive: 1000
- Maximum expanded bytes scanned: 25 MB
- Flags suspicious paths such as `../evil.txt` or absolute-path entries

## HTML and SVG policy

HTML cleanup uses PHP's DOM support to parse and rewrite content, removing disallowed tags and risky attributes instead of relying on `strip_tags()`, which PHP user notes caution is not sufficient for safe attribute handling. PHP's DOM APIs support HTML parsing and tree editing. citeturn204189search14turn204189search8turn204189search20

Highlights:

- Removes `script`, `iframe`, `object`, `embed`, `form`, and other non-allowlisted elements
- Removes all `on*` event handlers
- Removes `javascript:`, `vbscript:`, `file:`, and unsafe `data:` URLs
- Drops hostile CSS such as `expression()`, `@import`, `url()`, `behavior:`, and `-moz-binding`
- Removes SVG active content elements such as `script`, `foreignObject`, animation elements, external media, `image`, and `use`

## Tests

Included PHPUnit coverage exercises:

- nested ZIP detection
- path traversal detection inside ZIPs
- HTML sanitization rules
- SVG sanitization rules

## Limitations

- PDF cleanup is still best-effort rather than a full structural rewrite
- OOXML files are scanned for risky content and external references, but not fully rewritten yet
- This package is a sanitizer and heuristic scanner, not a substitute for sandboxing or AV scanning
