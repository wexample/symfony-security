<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\EventSubscriber;

use Wexample\SymfonySecurity\EventSubscriber\AbstractSecurityEventLogSubscriber;
use Wexample\SymfonySecurity\Tests\Fixtures\Event\FirstSecurityEvent;

class FirstSecurityEventLogSubscriber extends AbstractSecurityEventLogSubscriber
{
    public static function getSubscribedEvents(): array
    {
        return [FirstSecurityEvent::class => 'onSecurityEvent'];
    }
}
