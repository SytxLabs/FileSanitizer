<?php

namespace SytxLabs\FileSanitizer\Enums;

enum IssueSeverity: string
{
    case Info = 'low';
    case Warning = 'warning';
    case Error = 'error';
}
