<?php

namespace SytxLabs\FileSanitizer\Sanitizer;

use DOMDocument;
use DOMElement;
use DOMNode;
use DOMXPath;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\SanitizerInterface;
use SytxLabs\FileSanitizer\Dto\Issue;
use SytxLabs\FileSanitizer\Dto\SanitizeReport;
use SytxLabs\FileSanitizer\Enums\IssueSeverity;

final class SvgSanitizer implements SanitizerInterface
{
    public function supports(string $mimeType, string $path): bool
    {
        return $mimeType === 'image/svg+xml' || str_ends_with(strtolower($path), '.svg');
    }

    public function sanitize(string $inputPath, string $outputPath, bool $sanitizeAlways = false): SanitizeReport
    {
        $xml = file_get_contents($inputPath);
        if ($xml === false) {
            throw new RuntimeException('Could not read SVG.');
        }

        $dom = new DOMDocument();
        $loaded = @$dom->loadXML($xml, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING | LIBXML_NOBLANKS);
        if ($loaded !== true) {
            throw new RuntimeException('Invalid SVG XML.');
        }

        $xpath = new DOMXPath($dom);
        $removed = 0;

        foreach ([
            '//*[local-name()="script"]',
            '//*[local-name()="foreignObject"]',
            '//*[local-name()="iframe"]',
            '//*[local-name()="object"]',
            '//*[local-name()="embed"]',
            '//*[local-name()="audio"]',
            '//*[local-name()="video"]',
            '//*[local-name()="animate"]',
            '//*[local-name()="animateMotion"]',
            '//*[local-name()="animateTransform"]',
            '//*[local-name()="set"]',
            '//*[local-name()="discard"]',
            '//*[local-name()="metadata"]',
            '//*[local-name()="desc"]',
            '//*[local-name()="title"]',
            '//*[local-name()="style"]',
            '//*[local-name()="link"]',
            '//*[local-name()="image"]',
            '//*[local-name()="use"]',
        ] as $query) {
            $nodes = $xpath->query($query);
            if ($nodes === false) {
                continue;
            }
            for ($i = $nodes->length - 1; $i >= 0; $i--) {
                $node = $nodes->item($i);
                if ($node instanceof DOMNode && $node->parentNode !== null) {
                    $node->parentNode->removeChild($node);
                    $removed++;
                }
            }
        }

        foreach ($dom->getElementsByTagName('*') as $element) {
            if (!$element instanceof DOMElement) {
                continue;
            }

            $toRemove = [];
            foreach (iterator_to_array($element->attributes ?? []) as $attribute) {
                $name = strtolower($attribute->nodeName);
                $value = trim(html_entity_decode($attribute->nodeValue, ENT_QUOTES | ENT_HTML5, 'UTF-8'));
                if (str_starts_with($name, 'on')) {
                    $toRemove[] = $attribute->nodeName;
                    continue;
                }
                if (in_array($name, ['href', 'xlink:href', 'src'], true) && !$this->isSafeSvgReference($value)) {
                    $toRemove[] = $attribute->nodeName;
                    continue;
                }
                if ($name === 'style' && preg_match('/(?:expression\s*\(|@import\b|url\s*\(|behavior\s*:|-moz-binding\s*:)/i', $value) === 1) {
                    $toRemove[] = $attribute->nodeName;
                }
            }

            foreach (array_unique($toRemove) as $attributeName) {
                $element->removeAttribute($attributeName);
                $removed++;
            }
        }

        $dom->formatOutput = false;
        $output = $dom->saveXML($dom->documentElement);
        if ($output === false || file_put_contents($outputPath, $output) === false) {
            throw new RuntimeException('Could not write sanitized SVG.');
        }

        return new SanitizeReport($outputPath, true, [new Issue('svg_cleaned', sprintf('SVG cleaned with strict policy rules; %d risky or metadata nodes/attributes removed.', $removed), IssueSeverity::Info)]);
    }

    private function isSafeSvgReference(string $value): bool
    {
        if ($value === '' || str_starts_with($value, '#')) {
            return true;
        }

        return preg_match('#^(?:https?|data|javascript|vbscript|file):#i', $value) !== 1;
    }
}
