# FileSanitizer

[![MIT Licensed](https://img.shields.io/badge/License-MIT-brightgreen.svg?style=flat-square)](LICENSE)
[![Check code style](https://github.com/SytxLabs/FileSanitizer/actions/workflows/code-style.yml/badge.svg?style=flat-square)](https://github.com/SytxLabs/FileSanitizer/actions/workflows/code-style.yml)
[![Tests](https://github.com/SytxLabs/FileSanitizer/actions/workflows/tests.yml/badge.svg?style=flat-square)](https://github.com/SytxLabs/FileSanitizer/actions/workflows/tests.yml)
[![Latest Version on Packagist](https://poser.pugx.org/sytxlabs/filesanitizer/v/stable?format=flat-square)](https://packagist.org/packages/sytxlabs/filesanitizer)
[![Total Downloads](https://poser.pugx.org/sytxlabs/filesanitizer/downloads?format=flat-square)](https://packagist.org/packages/sytxlabs/filesanitizer)

Pure PHP file sanitizer and scanner for uploaded files. It strips metadata where practical, rewrites selected file types into safer forms, and detects suspicious or malicious content such as XSS-style payloads, risky embedded markup, active PDF content, and dangerous archive entries.

## Features

- Re-encodes supported image formats to remove metadata and ancillary chunks
- Sanitizes HTML and SVG using strict policy-based cleanup
- Scans PDFs for active content and applies best-effort cleanup 
- Scans OOXML documents for risky content such as macros, ActiveX, and external relationships 
- Recursively scans ZIP archives, including nested archives, with configurable safety limits
- Scans audio files for suspicious embedded payloads and removes metadata where practical
- Scans video files for suspicious embedded payloads and applies best-effort metadata cleanup
- Supports sanitize-always mode for best-effort cleaning even when risky content is detected
- Pure PHP implementation with no shell access, SSH, or external binaries required

## Installation

```bash
composer require sytxlabs/filesanitizer
````

For development and tests:

```bash
composer install
composer test
```

## Quick start

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

## sanitizeAlways mode

When `sanitizeAlways` is enabled, FileSanitizer will attempt best-effort sanitization even if risky content is detected during scanning.

This is useful when you want to:

* always strip metadata where possible
* always rewrite supported files where possible
* keep findings for review without immediately rejecting the upload

```php
<?php

use SytxLabs\FileSanitizer\FileSanitizer;

$sanitizer = new FileSanitizer();

$result = $sanitizer->process(__DIR__ . '/upload.pdf', null, true);
```

Best-effort sanitization does not guarantee a full structural rebuild for complex formats such as PDF, audio, or video containers.

## Supported file types

FileSanitizer currently supports scanning and/or sanitizing the following file types.

* Images
  * JPEG
  * PNG
  * GIF
  * WebP
* Documents and markup
  * HTML
  * SVG
  * PDF
  * TXT and text-like files
  * DOCX
  * XLSX
  * PPTX
* Archives
  * ZIP
  * Nested ZIP archives
* Audio
  * MP3
  * WAV
  * OGG
  * FLAC
  * M4A
  * AAC
* Video
  * MP4
  * MOV
  * WebM
  * MKV
  * AVI

## How it works

FileSanitizer combines format-aware scanning with best-effort sanitization.

### Scanning

The scanner looks for suspicious patterns and risky structures such as:

* inline JavaScript-style payloads
* dangerous HTML or SVG constructs
* active PDF actions
* suspicious archive paths and nested archive abuse
* risky embedded strings in audio and video containers
* macros, ActiveX, and external relationships in OOXML files

### Sanitizing

Supported sanitizers attempt to reduce risk by:

* re-encoding images
* removing unsafe HTML and SVG elements and attributes
* stripping metadata where practical
* rewriting selected file formats into safer forms
* applying best-effort cleanup to complex containers

## Archive scanning

ZIP scanning is recursive and designed to detect suspicious content without using shell extraction.

Current guards:

* maximum nesting depth: 3
* maximum scanned entries per archive: 1000
* maximum expanded bytes scanned: 25 MB
* suspicious path detection for entries such as `../evil.txt` or absolute paths

## HTML and SVG policy

HTML and SVG sanitization is policy-based and removes risky constructs instead of relying on simple tag stripping.

Highlights:

* removes `script`, `iframe`, `object`, `embed`, `form`, and other disallowed elements
* removes all `on*` event handlers
* removes `javascript:`, `vbscript:`, `file:`, and unsafe `data:` URLs
* removes hostile CSS such as `expression()`, `@import`, `url()`, `behavior:`, and `-moz-binding`
* removes SVG active content such as `script`, `foreignObject`, animation elements, external media, `image`, and `use`

## Audio support

FileSanitizer includes best-effort support for common audio formats.

### What it does

* Detects suspicious embedded payloads such as:

    * `<script`
    * `javascript:`
    * inline event handler patterns like `onclick=`
    * `<iframe`
    * `data:text/html`
    * embedded PHP tags

* Removes metadata where practical:

    * MP3: ID3v1 and ID3v2 tags
    * WAV: selected metadata chunks such as `LIST`, `INFO`, and `ID3`
    * OGG, FLAC, M4A, and AAC: conservative best-effort textual payload cleanup

### Notes

Audio sanitization is best-effort and does not transcode or fully rebuild complex media containers. No shell tools, SSH access, or external binaries are required.

## Video support

FileSanitizer includes best-effort support for common video containers.

### What it does

* Detects suspicious embedded payloads such as:

    * `<script`
    * `javascript:`
    * inline event handler patterns like `onload=`
    * `<iframe`
    * `data:text/html`
    * embedded PHP tags

* Applies conservative container cleanup where practical:

    * MP4 and MOV: attempts to remove selected metadata atoms such as `udta`, `meta`, and `ilst`
    * AVI: removes selected metadata chunks such as `INFO`, `JUNK`, and `IDIT`
    * WebM and MKV: applies conservative best-effort textual payload cleanup

### Notes

Video sanitization is best-effort and does not transcode or fully rebuild media containers. Without external tools such as FFmpeg, full structural video rewriting is intentionally out of scope.

## Test coverage

Included PHPUnit coverage exercises:

* nested ZIP detection
* path traversal detection inside ZIPs
* HTML sanitization rules
* SVG sanitization rules
* PDF action detection
* audio metadata stripping
* video file scanning for embedded payloads and metadata stripping

## Limitations

FileSanitizer is a pure PHP package focused on safe, practical, best-effort sanitization.

### Important limitations

* PDF sanitization is a best-effort and not a full PDF rebuild
* OOXML files are scanned for risky content but are not fully rewritten
* audio sanitization removes metadata where practical but does not transcode files
* video sanitization is best-effort and does not perform full re-encoding or container rebuilding
* complex media formats may still require deeper inspection in high-security environments
