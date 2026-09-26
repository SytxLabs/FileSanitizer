<?php

namespace SytxLabs\FileSanitizer\Stream;

use RuntimeException;
use SytxLabs\FileSanitizer\Contracts\OutputInterface;

final class FileWriter implements OutputInterface
{
    /** @var resource */
    private $handle;

    private int $bytesWritten = 0;

    public function __construct(private readonly string $path)
    {
        $directory = dirname($this->path);
        if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Failed to create output directory: %s', $directory));
        }
        $handle = fopen($this->path, 'wb');
        if ($handle === false) {
            throw new RuntimeException(sprintf('Could not open file for writing: %s', $this->path));
        }
        $this->handle = $handle;
    }

    public function __destruct()
    {
        $this->close();
    }

    public function write(string $data): void
    {
        fwrite($this->handle, $data);
        $this->bytesWritten += strlen($data);
    }

    public function close(): void
    {
        if (is_resource($this->handle)) {
            fclose($this->handle);
        }
    }

    public function size(): false|int
    {
        return $this->bytesWritten;
    }
}
