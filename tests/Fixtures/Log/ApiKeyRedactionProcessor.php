<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Log;

use Wexample\SymfonySecurity\Log\AbstractSecretRedactionProcessor;

/**
 * As an application masks a key of its own by a pattern, keeping a hint.
 */
class ApiKeyRedactionProcessor extends AbstractSecretRedactionProcessor
{
    protected function mask(string $value): string
    {
        return preg_replace_callback(
            '/key_([0-9a-z]{4})[0-9a-z]{12}/',
            static fn (array $match) => 'key_' . $match[1] . '…',
            $value
        );
    }
}
