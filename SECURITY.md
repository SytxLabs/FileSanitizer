# Security Policy

FileSanitizer exists to make untrusted file uploads safer, so security issues in the library itself are treated with priority.

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 1.x.x   | :white_check_mark: |
| 2.x.x   | :white_check_mark: |

Only the latest 1.x release is actively supported with security fixes. Please upgrade to the latest version before reporting an issue, and mention the exact version (and PHP version) you tested against.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities privately to **info@sytxlabs.eu** (or via [GitHub's private vulnerability reporting](https://github.com/SytxLabs/FileSanitizer/security/advisories/new) if enabled for this repository). Include:

* the affected version(s) and PHP version
* a minimal reproduction case (a crafted file or input, and the code calling into FileSanitizer)
* the impact you believe it has (e.g. sanitizer bypass, scanner bypass, DoS via crafted input, memory exhaustion)

You should expect an initial response within a few business days. Once a fix is available, a new release will be published and the reporter credited in the release notes, unless anonymity is requested. Please allow a reasonable coordinated-disclosure window before publishing details publicly.

## Scope

In scope:

* bypasses of the SVG/HTML allow-list policy (a disallowed element, attribute, or URL scheme surviving sanitization)
* PDF, audio, or video active-content detection/sanitization bypasses
* archive scanning bypasses (path traversal, zip-bomb-style resource exhaustion beyond the documented guards)
* crashes, hangs, or excessive memory/CPU usage triggered by malformed or adversarial input to any scanner or sanitizer
* filename sanitization bypasses that could lead to path traversal or overwriting unintended files

Out of scope:

* issues that require the calling application to already trust attacker-controlled PHP code, file paths, or configuration
* vulnerabilities in PHP itself, its extensions (GD, fileinfo, zip, ...), or third-party dependencies — report those upstream
* denial of service through sheer input size on unbounded environments with no resource limits configured (the library streams in bounded chunks, but an operator is still expected to enforce upload size limits at the application/webserver level)

## How the project defends against this class of bug

FileSanitizer's scanners and sanitizers are hand-rolled, bounded-buffer byte-level parsers (no DOM, no `ext-xml`) specifically built to survive malformed and adversarial input without crashing, hanging, or silently misbehaving. That property is exercised directly, not just assumed:

* the PHPUnit suite (`composer test`) covers ~98% of lines, including chunk-boundary and malformed-input edge cases for every parser
* `tests/FuzzTest.php`, part of the default suite, fuzzes the PDF decoders, the SVG/HTML tokenizers, `PdfScanner`, and the WAV/AVI/MP4 chunk walkers with random bytes and mutated known-good fixtures
* static analysis runs via PHPStan at level 8 (`composer stan`)

None of this guarantees the absence of vulnerabilities — please report what you find.
