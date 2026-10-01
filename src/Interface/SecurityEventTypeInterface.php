<?php

namespace Wexample\SymfonySecurity\Interface;

use BackedEnum;

/**
 * The enum of the stable codes a package records as security events.
 */
interface SecurityEventTypeInterface extends BackedEnum
{
    public function isFailure(): bool;
}
