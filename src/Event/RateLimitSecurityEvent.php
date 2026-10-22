<?php

namespace Wexample\SymfonySecurity\Event;

/**
 * A request refused by a #[RateLimit]: `extra` names the limit (`limit`)
 * and the route. Dispatched before the 429 is sent, so that what was
 * refused is recorded somewhere rather than lost.
 */
class RateLimitSecurityEvent extends AbstractSecurityEvent
{
}
