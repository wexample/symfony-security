<?php

namespace Wexample\SymfonySecurity\EventSubscriber;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Adds the security headers of the configuration to every main response.
 *
 * A header the response already carries is left as it is: a controller
 * allowing one page in a frame says so on that response. Strict-Transport-Security
 * is only sent over HTTPS, where a browser reads it.
 */
class SecurityHeadersSubscriber implements EventSubscriberInterface
{
    private const string STRICT_TRANSPORT_SECURITY = 'Strict-Transport-Security';

    /**
     * @param array<string, string> $headers header name => value
     */
    public function __construct(
        private readonly array $headers
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [KernelEvents::RESPONSE => 'onResponse'];
    }

    public function onResponse(ResponseEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $response = $event->getResponse();
        $secure = $event->getRequest()->isSecure();

        foreach ($this->headers as $name => $value) {
            if (self::STRICT_TRANSPORT_SECURITY === $name && ! $secure) {
                continue;
            }

            if (! $response->headers->has($name)) {
                $response->headers->set($name, $value);
            }
        }
    }
}
