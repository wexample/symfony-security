<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Event;

use Wexample\SymfonySecurity\Event\AbstractSecurityEvent;
use Wexample\SymfonySecurity\Tests\Fixtures\Enum\FirstSecurityEventType;

class FirstSecurityEvent extends AbstractSecurityEvent
{
    public function __construct(FirstSecurityEventType $type, mixed ...$arguments)
    {
        parent::__construct($type, ...$arguments);
    }
}
