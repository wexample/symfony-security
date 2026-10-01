<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Enum;

use Wexample\SymfonySecurity\Interface\SecurityEventTypeInterface;

enum SecondSecurityEventType: string implements SecurityEventTypeInterface
{
    case TOKEN_REFUSED = 'token.refused';

    public function isFailure(): bool
    {
        return true;
    }
}
