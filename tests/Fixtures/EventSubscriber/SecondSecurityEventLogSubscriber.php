<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\EventSubscriber;

use Wexample\SymfonySecurity\EventSubscriber\AbstractSecurityEventLogSubscriber;
use Wexample\SymfonySecurity\Tests\Fixtures\Event\SecondSecurityEvent;

class SecondSecurityEventLogSubscriber extends AbstractSecurityEventLogSubscriber
{
    public static function getSubscribedEvents(): array
    {
        return [SecondSecurityEvent::class => 'onSecurityEvent'];
    }
}
