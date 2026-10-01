<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Enum;

use Wexample\SymfonySecurity\Interface\SecurityEventTypeInterface;

enum FirstSecurityEventType: string implements SecurityEventTypeInterface
{
    case LOGIN_SUCCEEDED = 'login.succeeded';
    case LOGIN_FAILED = 'login.failed';

    public function isFailure(): bool
    {
        return self::LOGIN_FAILED === $this;
    }
}
