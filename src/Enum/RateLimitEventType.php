<?php

namespace Wexample\SymfonySecurity\Enum;

use Wexample\SymfonySecurity\Interface\SecurityEventTypeInterface;

enum RateLimitEventType: string implements SecurityEventTypeInterface
{
    case EXCEEDED = 'rate_limit.exceeded';

    public function isFailure(): bool
    {
        return true;
    }
}
