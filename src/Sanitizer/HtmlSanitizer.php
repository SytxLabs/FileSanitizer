<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use DOMDocument;
use DOMElement;
use DOMNode;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class HtmlSanitizer implements SanitizerInterface
{
    private const ALLOWED_TAGS = [
        'html', 'head', 'body', 'title', 'meta',
        'div', 'span', 'p', 'br', 'hr',
        'strong', 'b', 'em', 'i', 'u', 'small',
        'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
        'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
        'a', 'img',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    ];

    private const GLOBAL_ATTRIBUTES = ['class', 'id', 'title', 'lang', 'dir', 'aria-label', 'aria-hidden', 'role'];
    private const URL_ATTRIBUTES = ['href', 'src'];

    public function supports(string $mimeType, string $path): bool
    {
        return in_array($mimeType, ['text/html', 'application/xhtml+xml'], true);
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $html = file_get_contents($inputPath);
        if ($html === false) {
            throw new RuntimeException('Could not read HTML file.');
        }

        $dom = new DOMDocument('1.0', 'UTF-8');
        $wrappedHtml = '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $html . '</body></html>';
        $loaded = @$dom->loadHTML($wrappedHtml, LIBXML_HTML_NODEFDTD | LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        if ($loaded !== true) {
            throw new RuntimeException('Invalid HTML.');
        }

        $removed = 0;
        $nodes = iterator_to_array($dom->getElementsByTagName('*'));
        foreach ($nodes as $node) {
            if (!$node instanceof DOMElement) {
                continue;
            }

            $tag = strtolower($node->tagName);
            if (!in_array($tag, self::ALLOWED_TAGS, true)) {
                $this->removeNodePreservingText($node);
                $removed++;
                continue;
            }

            if ($tag === 'meta') {
                $httpEquiv = strtolower(trim($node->getAttribute('http-equiv')));
                if ($httpEquiv === 'refresh') {
                    $node->parentNode?->removeChild($node);
                    $removed++;
                    continue;
                }
            }

            $toRemove = [];
            foreach (iterator_to_array($node->attributes ?? []) as $attribute) {
                $name = strtolower($attribute->name);
                $value = trim($attribute->value);

                if (str_starts_with($name, 'on')) {
                    $toRemove[] = $attribute->name;
                    continue;
                }

                if ($name === 'style') {
                    $cleanStyle = $this->sanitizeStyle($value);
                    if ($cleanStyle === null) {
                        $toRemove[] = $attribute->name;
                    } else {
                        $node->setAttribute('style', $cleanStyle);
                    }
                    continue;
                }

                if (in_array($name, self::URL_ATTRIBUTES, true)) {
                    if (!$this->isSafeUrl($value, $tag === 'img' && $name === 'src')) {
                        $toRemove[] = $attribute->name;
                        continue;
                    }
                }

                if (!$this->isAllowedAttribute($tag, $name)) {
                    $toRemove[] = $attribute->name;
                }
            }

            foreach (array_unique($toRemove) as $attributeName) {
                $node->removeAttribute($attributeName);
                $removed++;
            }

            if ($tag === 'a' && $node->hasAttribute('href')) {
                $node->setAttribute('rel', 'nofollow noopener noreferrer');
            }
        }

        $output = '';
        $body = $dom->getElementsByTagName('body')->item(0);
        if ($body instanceof DOMElement) {
            foreach (iterator_to_array($body->childNodes) as $child) {
                $fragment = $dom->saveHTML($child);
                if ($fragment !== false) {
                    $output .= $fragment;
                }
            }
        }

        if ($output === '' && trim($html) !== '') {
            $output = trim(strip_tags($html));
        }

        if (file_put_contents($outputPath, $output) === false) {
            throw new RuntimeException('Could not write sanitized HTML.');
        }

        return new SanitizeReport($outputPath, false, [
            new Issue('html_cleaned', sprintf('HTML cleaned with allowlist rules; %d risky nodes or attributes removed.', $removed), IssueSeverity::Info),
        ]);
    }

    private function isAllowedAttribute(string $tag, string $name): bool
    {
        if (in_array($name, self::GLOBAL_ATTRIBUTES, true)) {
            return true;
        }

        return match ($tag) {
            'a' => in_array($name, ['href', 'target', 'rel'], true),
            'img' => in_array($name, ['src', 'alt', 'width', 'height'], true),
            'td', 'th' => in_array($name, ['colspan', 'rowspan', 'scope'], true),
            'meta' => in_array($name, ['charset', 'name', 'content'], true),
            default => false,
        };
    }

    private function isSafeUrl(string $value, bool $allowImageDataUri): bool
    {
        $value = trim(html_entity_decode($value, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        if ($value === '' || str_starts_with($value, '#') || str_starts_with($value, '/')) {
            return true;
        }

        if ($allowImageDataUri && preg_match('#^data:image/(?:png|gif|jpeg|webp);base64,#i', $value) === 1) {
            return true;
        }

        if (preg_match('#^(?:https?|mailto|tel):#i', $value) === 1) {
            return true;
        }

        return !preg_match('#^(?:javascript|data|vbscript|file):#i', $value);
    }

    private function sanitizeStyle(string $style): ?string
    {
        $decoded = html_entity_decode($style, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        if (preg_match('/(?:expression\s*\(|@import\b|url\s*\(|behavior\s*:|-moz-binding\s*:)/i', $decoded) === 1) {
            return null;
        }

        $sanitized = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $decoded) ?? $decoded;
        return trim($sanitized);
    }

    private function removeNodePreservingText(DOMElement $node): void
    {
        $parent = $node->parentNode;
        if ($parent === null) {
            return;
        }

        while ($node->firstChild instanceof DOMNode) {
            $parent->insertBefore($node->firstChild, $node);
        }

        $parent->removeChild($node);
    }
}
