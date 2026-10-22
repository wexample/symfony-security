<?php

namespace Wexample\SymfonySecurity\Enum;

/**
 * Who a limit counts the requests of.
 */
enum RateLimitScope: string
{
    /** Every client behind one address shares the count. */
    case IP = 'ip';

    /** The signed-in user, wherever they connect from; the address when nobody is signed in. */
    case USER = 'user';
}
