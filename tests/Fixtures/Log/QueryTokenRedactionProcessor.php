<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Log;

use Wexample\SymfonySecurity\Log\AbstractSecretRedactionProcessor;

/**
 * As a package masks the signature of its links.
 */
class QueryTokenRedactionProcessor extends AbstractSecretRedactionProcessor
{
    protected function mask(string $value): string
    {
        return $this->maskQueryParameters($value, ['token', 'sig']);
    }
}
