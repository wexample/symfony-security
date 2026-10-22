<?php

namespace Wexample\SymfonySecurity\Attribute;

use Attribute;
use Wexample\SymfonySecurity\Enum\RateLimitScope;

/**
 * Limits the requests a controller answers, per address or per user, over
 * a sliding window: `#[RateLimit(30, '1 minute')]`. Beyond it the request
 * is answered 429 with a Retry-After, and a RateLimitSecurityEvent says so.
 *
 * On a class, it covers every action; an action may carry its own as well,
 * and each limit counts on its own.
 */
#[Attribute(Attribute::TARGET_CLASS | Attribute::TARGET_METHOD | Attribute::IS_REPEATABLE)]
final readonly class RateLimit
{
    /**
     * @param string $interval as the rate limiter reads it: `1 minute`, `1 hour`
     * @param string|null $name the count it shares with other actions carrying the same name;
     *                          each action counts on its own when unset
     */
    public function __construct(
        public int $limit,
        public string $interval,
        public RateLimitScope $scope = RateLimitScope::IP,
        public ?string $name = null,
    ) {
    }
}
