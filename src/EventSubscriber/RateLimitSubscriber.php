<?php

namespace Wexample\SymfonySecurity\EventSubscriber;

use DateTimeImmutable;
use Psr\Cache\CacheItemPoolInterface;
use Psr\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\DependencyInjection\Attribute\Autowire;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Wexample\SymfonyHelpers\Attribute\WorkerSafe;
use Wexample\SymfonySecurity\Attribute\RateLimit;
use Wexample\SymfonySecurity\DependencyInjection\WexampleSymfonySecurityExtension;
use Wexample\SymfonySecurity\Enum\RateLimitEventType;
use Wexample\SymfonySecurity\Enum\RateLimitScope;
use Wexample\SymfonySecurity\Event\RateLimitSecurityEvent;
use Wexample\SymfonySecurity\Helper\RequestIdHelper;

/**
 * Applies the #[RateLimit] of the controller about to run, and the limits the
 * application declares on groups of requests (`rate_limits`). The counts live
 * in the application cache, so they hold across workers wherever the cache
 * is shared — Redis, APCu on a single server —, and not at all with an
 * array cache, which the kernel empties between two requests.
 */
class RateLimitSubscriber implements EventSubscriberInterface
{
    /** @var array<string, RateLimiterFactory> */
    #[WorkerSafe('One factory per declared limit; the counts live in the cache, keyed by visitor.')]
    private array $factories = [];

    private readonly CacheStorage $storage;

    /**
     * @param list<array{name: string, limit: int, interval: string, scope: string, methods: list<string>, routes: ?string, paths: ?string}> $rules
     */
    public function __construct(
        CacheItemPoolInterface $cache,
        private readonly EventDispatcherInterface $dispatcher,
        private readonly ?TokenStorageInterface $tokenStorage = null,
        #[Autowire(param: WexampleSymfonySecurityExtension::PARAMETER_RATE_LIMITS)]
        private readonly array $rules = [],
    ) {
        $this->storage = new CacheStorage($cache);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            // The rules counted by address, before the firewall (8): signing
            // in and the second factor are answered by it, no controller ever
            // reached — and each sign-in may send a mail. After the router (32),
            // for the route name to be known.
            KernelEvents::REQUEST => ['onRequest', 9],
            // Before the controller, after the firewall: the user a limit
            // counts by is known.
            KernelEvents::CONTROLLER_ARGUMENTS => 'onControllerArguments',
        ];
    }

    public function onRequest(RequestEvent $event): void
    {
        if (! $event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        $route = (string) $request->attributes->get('_route', '');
        $limits = $this->matchingRules($request, $route, RateLimitScope::IP);

        if ($refused = $this->consume($request, $route, $limits)) {
            $event->setResponse($refused);
        }
    }

    public function onControllerArguments(ControllerArgumentsEvent $event): void
    {
        $request = $event->getRequest();
        $route = (string) $request->attributes->get('_route', '');

        /** @var RateLimit[] $limits */
        $limits = [...$event->getAttributes(RateLimit::class), ...$this->matchingRules($request, $route, RateLimitScope::USER)];

        if ($refused = $this->consume($request, $route, $limits)) {
            // Answered rather than thrown: an exception would be logged as an
            // error on each refused request, a flood of them during a flood.
            // The event dispatched is what tells it.
            $event->setController(static fn () => $refused);
        }
    }

    /**
     * Each limit consumed once; the first one exhausted refuses the request.
     *
     * @param list<RateLimit> $limits
     */
    private function consume(Request $request, string $route, array $limits): ?Response
    {
        foreach ($limits as $limit) {
            $id = $limit->name ?? $route;
            $consumption = $this->factory($id, $limit)
                ->create($this->key($limit->scope, $request))
                ->consume();

            if (! $consumption->isAccepted()) {
                $this->dispatcher->dispatch($this->event($request, $id, $limit));
                $retryAfter = max(1, $consumption->getRetryAfter()->getTimestamp() - time());

                return new Response(null, Response::HTTP_TOO_MANY_REQUESTS, ['Retry-After' => (string) $retryAfter]);
            }
        }

        return null;
    }

    /**
     * The rules of the configuration this request falls under, as the limits
     * an attribute would have declared: each one named, so counted on its own.
     *
     * @return list<RateLimit>
     */
    private function matchingRules(Request $request, string $route, RateLimitScope $scope): array
    {
        $limits = [];

        foreach ($this->rules as $rule) {
            if ($scope->value !== $rule['scope']
                || ([] !== $rule['methods'] && ! in_array($request->getMethod(), $rule['methods'], true))
                || (null !== $rule['routes'] && ! preg_match($rule['routes'], $route))
                || (null !== $rule['paths'] && ! preg_match($rule['paths'], $request->getPathInfo()))
            ) {
                continue;
            }

            $limits[] = new RateLimit(
                limit: $rule['limit'],
                interval: $rule['interval'],
                scope: RateLimitScope::from($rule['scope']),
                name: $rule['name'],
            );
        }

        return $limits;
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
