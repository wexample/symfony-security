<?php

namespace Wexample\SymfonySecurity\EventSubscriber;

use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Wexample\SymfonySecurity\Event\AbstractSecurityEvent;

/**
 * Writes security events to a log channel of their own, warnings for
 * failures, so that their retention — they hold IP addresses — is set apart
 * from the technical logs.
 *
 * A subclass names its channel with #[WithMonologChannel] and its event class
 * in getSubscribedEvents(), mapped to onSecurityEvent.
 */
abstract class AbstractSecurityEventLogSubscriber implements EventSubscriberInterface
{
    public function __construct(
        protected readonly LoggerInterface $logger
    ) {
    }

    public function onSecurityEvent(AbstractSecurityEvent $event): void
    {
        $this->logger->log(
            $event->type->isFailure() ? 'warning' : 'info',
            $event->type->value,
            $event->toArray()
        );
    }
}
