<?php

namespace Wexample\SymfonySecurity\EventSubscriber;

use DateTimeImmutable;
use Psr\Cache\CacheItemPoolInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Wexample\SymfonySecurity\Attribute\RateLimit;
use Wexample\SymfonySecurity\Enum\RateLimitEventType;
use Wexample\SymfonySecurity\Enum\RateLimitScope;
use Wexample\SymfonySecurity\Event\RateLimitSecurityEvent;
use Wexample\SymfonySecurity\Helper\RequestIdHelper;

/**
 * Applies the #[RateLimit] of the controller about to run. The counts live
 * in the application cache, so they hold across workers wherever the cache
 * is shared — Redis, APCu on a single server —, and not at all with an
 * array cache, which the kernel empties between two requests.
 */
class RateLimitSubscriber implements EventSubscriberInterface
{
    /** @var array<string, RateLimiterFactory> */
    private array $factories = [];

    private readonly CacheStorage $storage;

    public function __construct(
        CacheItemPoolInterface $cache,
        private readonly EventDispatcherInterface $dispatcher,
        private readonly ?TokenStorageInterface $tokenStorage = null,
    ) {
        $this->storage = new CacheStorage($cache);
    }

    public static function getSubscribedEvents(): array
    {
        // Before the controller, after the firewall (which runs on REQUEST):
        // the user a limit counts by is known.
        return [KernelEvents::CONTROLLER_ARGUMENTS => 'onControllerArguments'];
    }

    public function onControllerArguments(ControllerArgumentsEvent $event): void
    {
        /** @var RateLimit[] $limits */
        $limits = $event->getAttributes(RateLimit::class);

        if ([] === $limits) {
            return;
        }

        $request = $event->getRequest();
        $route = (string) $request->attributes->get('_route', '');

        foreach ($limits as $limit) {
            $id = $limit->name ?? $route;
            $consumption = $this->factory($id, $limit)
                ->create($this->key($limit->scope, $request))
                ->consume();

            if (! $consumption->isAccepted()) {
                $this->dispatcher->dispatch($this->event($request, $id, $limit));

                throw new TooManyRequestsHttpException(max(1, $consumption->getRetryAfter()->getTimestamp() - time()));
            }
        }
    }

    private function factory(
        string $id,
        RateLimit $limit
    ): RateLimiterFactory {
        $key = $id.'|'.$limit->limit.'|'.$limit->interval;

        return $this->factories[$key] ??= new RateLimiterFactory([
            'id' => 'wexample_rate_limit.'.$id,
            'policy' => 'sliding_window',
            'limit' => $limit->limit,
            'interval' => $limit->interval,
        ], $this->storage);
    }

    private function key(
        RateLimitScope $scope,
        Request $request
    ): string {
        $user = RateLimitScope::USER === $scope ? $this->tokenStorage?->getToken()?->getUserIdentifier() : null;

        // The identifier is often an address: it is hashed before it becomes a cache key.
        return null !== $user && '' !== $user ? 'user:'.hash('sha256', $user) : 'ip:'.$request->getClientIp();
    }

    /**
     * The id of the signed-in user, as every security event names them; an
     * identifier would be an address, which security events never hold.
     */
    private function userId(): ?string
    {
        $user = $this->tokenStorage?->getToken()?->getUser();

        return null !== $user && method_exists($user, 'getId') ? (string) $user->getId() : null;
    }

    private function event(
        Request $request,
        string $id,
        RateLimit $limit
    ): RateLimitSecurityEvent {
        return new RateLimitSecurityEvent(
            type: RateLimitEventType::EXCEEDED,
            occurredAt: new DateTimeImmutable(),
            userId: $this->userId(),
            method: $request->getMethod(),
            ip: $request->getClientIp(),
            userAgent: $request->headers->get('User-Agent'),
            requestId: RequestIdHelper::resolve($request),
            extra: [
                'limit' => $id,
                'route' => $request->attributes->get('_route'),
                'max' => $limit->limit,
                'interval' => $limit->interval,
            ],
        );
    }
}
