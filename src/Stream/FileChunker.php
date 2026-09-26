<?php

namespace SytxLabs\FileSanitizer\Stream;

use Generator;
use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\StreamInterface;

final class FileChunker implements StreamInterface
{
    private const DEFAULT_CHUNK_SIZE = 1048576;

    /** @var resource */
    private $handle;

    public function __construct(private readonly string $path, private readonly int $chunkSize = self::DEFAULT_CHUNK_SIZE)
    {
        if (!is_file($this->path)) {
            throw new RuntimeException(sprintf('Input file not found: %s', $this->path));
        }
        $handle = fopen($this->path, 'rb');
        if ($handle === false) {
            throw new RuntimeException(sprintf('Could not open file for reading: %s', $this->path));
        }
        $this->handle = $handle;
    }

    public function __destruct()
    {
        $this->close();
    }

    public function __toString(): string
    {
        return $this->readAll();
    }

    public function filePath(): string
    {
        return $this->path;
    }

    public function read(int $length): false|string
    {
        return feof($this->handle) ? false : fread($this->handle, $length);
    }

    public function eof(): bool
    {
        return feof($this->handle);
    }

    public function tell(): false|int
    {
        return ftell($this->handle);
    }

    public function size(): false|int
    {
        return filesize($this->path);
    }

    public function seek(int $offset): void
    {
        fseek($this->handle, $offset);
    }

    public function rewind(): void
    {
        rewind($this->handle);
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }
    }

    /** @return Generator<int, string> */
    public function chunks(): Generator
    {
        $this->rewind();
        while (!$this->eof()) {
            $chunk = $this->read($this->chunkSize);
            if ($chunk === false || $chunk === '') {
                break;
            }
            yield $chunk;
        }
    }

    public function readAll(): string
    {
        $this->rewind();
        return implode('', iterator_to_array($this->chunks()));
    }
}
