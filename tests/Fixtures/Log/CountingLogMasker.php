<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Log;

use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

/**
 * Masks nothing, counts the strings it is handed.
 */
class CountingLogMasker implements LogMaskerInterface
{
    public int $calls = 0;

    public function mask(string $value): string
    {
        $this->calls++;

        return $value;
    }
}
