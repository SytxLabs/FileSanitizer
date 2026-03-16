# FileSanitizer

[![MIT Licensed](https://img.shields.io/badge/License-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Check code style](https://github.com/SytxLabs/FileSanitizer/actions/workflows/code-style.yml/badge.svg?style=flat-square)](https://github.com/SytxLabs/FileSanitizer/actions/workflows/code-style.yml)
[![Tests](https://github.com/SytxLabs/FileSanitizer/actions/workflows/tests.yml/badge.svg?style=flat-square)](https://github.com/SytxLabs/FileSanitizer/actions/workflows/code-style.yml)
[![Latest Version on Packagist](https://poser.pugx.org/sytxlabs/filesanitizer/v/stable?format=flat-square)](https://packagist.org/packages/sytxlabs/filesanitizer)
[![Total Downloads](https://poser.pugx.org/sytxlabs/filesanitizer/downloads?format=flat-square)](https://packagist.org/packages/sytxlabs/filesanitizer)


Pure PHP file sanitizer and scanner for uploaded files. It strips metadata where practical, rewrites selected file types into safer forms, and blocks files that look malicious.

## Features

- Re-encodes JPEG, PNG, GIF, and WebP images to strip EXIF and ancillary metadata
- Scans HTML, SVG, PDF, text, Office OOXML, ZIP, and nested ZIP content for risky payloads
- Recursively scans ZIP archives with depth, entry-count, and expanded-size guards
- Detects common XSS-style payloads such as `<script>`, inline handlers, `javascript:` URLs, hostile CSS, and dangerous PDF actions
- Applies strict allowlist-based cleanup for HTML and strict removal rules for SVG

## Install

```bash
composer require sytxlabs/filesanitizer
```

For development and tests:

```bash
composer install
composer test
```

PHPUnit is added as a dev dependency

## Usage

```php
<?php

require __DIR__ . '/vendor/autoload.php';

use SytxLabs\FileSanitizer\FileSanitizer;

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

The recursive archive scanner uses PHP's `ZipArchive` extension and does not extract archives to a shell. PHP documents `ZipArchive` for reading archive entries and notes extraction and open behavior through the zip extension API.

Current guards:

- Maximum nesting depth: 3
- Maximum scanned entries per archive: 1000
- Maximum expanded bytes scanned: 25 MB
- Flags suspicious paths such as `../evil.txt` or absolute-path entries

## HTML and SVG policy

HTML cleanup uses PHP's DOM support to parse and rewrite content, removing disallowed tags and risky attributes instead of relying on `strip_tags()`, which PHP user notes caution is not enough for safe attribute handling. PHP's DOM APIs support HTML parsing and tree editing.

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
- PDF action detection

## Limitations

- PDF cleanup is still best-effort rather than a full structural rewrite
- OOXML files are scanned for risky content and external references but not fully rewritten yet
- This package is a sanitizer and heuristic scanner, not a substitute for sandboxing or AV scanning
