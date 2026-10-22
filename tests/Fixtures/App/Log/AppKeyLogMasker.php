<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App\Log;

use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

/**
 * As an application masks a key of its own, keeping a hint: a service, no
 * processor.
 */
class AppKeyLogMasker implements LogMaskerInterface
{
    public function mask(string $value): string
    {
        return preg_replace('/key_([0-9a-z]{4})[0-9a-z]{12}/', 'key_$1…', $value);
    }
}
