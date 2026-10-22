<?php

namespace Wexample\SymfonySecurity\Event;

use DateTimeImmutable;
use Symfony\Contracts\EventDispatcher\Event;
use Wexample\SymfonySecurity\Interface\SecurityEventTypeInterface;

/**
 * A security fact, the same shape whichever package records it, so that one
 * recorder — a log subscriber, an audit package — reads them all. Each
 * package dispatches its own subclass, under its own class name.
 *
 * It never holds a secret: `userId` names the actor or subject, a token is
 * named by a hint, an unknown identifier by a fingerprint, in `extra`.
 */
abstract class AbstractSecurityEvent extends Event
{
    /**
     * @param array<string, scalar|array|null> $extra
     */
    public function __construct(
        public readonly SecurityEventTypeInterface $type,
        public readonly DateTimeImmutable $occurredAt,
        public readonly ?string $userId = null,
        public readonly ?string $cause = null,
        public readonly ?string $method = null,
        public readonly ?string $firewall = null,
        public readonly ?string $ip = null,
        public readonly ?string $userAgent = null,
        public readonly ?string $requestId = null,
        public readonly array $extra = [],
    ) {
    }

    /**
     * @return array<string, scalar|array|null>
     */
    public function toArray(): array
    {
        return [
            'type' => $this->type->value,
            'outcome' => $this->type->isFailure() ? 'failure' : 'success',
            'cause' => $this->cause,
            'user_id' => $this->userId,
            'method' => $this->method,
            'firewall' => $this->firewall,
            'ip' => $this->ip,
            'user_agent' => $this->userAgent,
            'request_id' => $this->requestId,
            'occurred_at' => $this->occurredAt->format(DATE_ATOM),
            'extra' => $this->extra,
        ];
    }
}
