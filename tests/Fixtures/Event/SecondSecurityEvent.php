<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\Event;

use Wexample\SymfonySecurity\Event\AbstractSecurityEvent;
use Wexample\SymfonySecurity\Tests\Fixtures\Enum\SecondSecurityEventType;

class SecondSecurityEvent extends AbstractSecurityEvent
{
    public function __construct(SecondSecurityEventType $type, mixed ...$arguments)
    {
        parent::__construct($type, ...$arguments);
    }
}
