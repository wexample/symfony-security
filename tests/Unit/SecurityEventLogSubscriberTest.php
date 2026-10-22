<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use DateTimeImmutable;
use DateTimeZone;
use Monolog\Handler\TestHandler;
use Monolog\Level;
use Monolog\Logger;
use PHPUnit\Framework\TestCase;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Wexample\SymfonySecurity\Tests\Fixtures\Enum\FirstSecurityEventType;
use Wexample\SymfonySecurity\Tests\Fixtures\Enum\SecondSecurityEventType;
use Wexample\SymfonySecurity\Tests\Fixtures\Event\FirstSecurityEvent;
use Wexample\SymfonySecurity\Tests\Fixtures\Event\SecondSecurityEvent;
use Wexample\SymfonySecurity\Tests\Fixtures\EventSubscriber\FirstSecurityEventLogSubscriber;
use Wexample\SymfonySecurity\Tests\Fixtures\EventSubscriber\SecondSecurityEventLogSubscriber;

/**
 * Two packages' events, each written to its own channel by the shared
 * subscriber, in one shape.
 */
class SecurityEventLogSubscriberTest extends TestCase
{
    public function testEachEventIsWrittenToItsChannelWithTheCommonFields(): void
    {
        $handler = new TestHandler();
        $dispatcher = new EventDispatcher();
        $dispatcher->addSubscriber(new FirstSecurityEventLogSubscriber(new Logger('first_security', [$handler])));
        $dispatcher->addSubscriber(new SecondSecurityEventLogSubscriber(new Logger('second_security', [$handler])));
        $occurredAt = new DateTimeImmutable('2026-10-01 12:00:00', new DateTimeZone('UTC'));
        $common = [
            'occurredAt' => $occurredAt,
            'userId' => '42',
            'cause' => 'bad_credentials',
            'method' => 'password',
            'firewall' => 'main',
            'ip' => '203.0.113.7',
            'userAgent' => 'Test/1.0',
            'requestId' => 'req-1',
        ];

        $dispatcher->dispatch(new FirstSecurityEvent(FirstSecurityEventType::LOGIN_FAILED, ...$common, extra: ['a' => 1]));
        $dispatcher->dispatch(new FirstSecurityEvent(type: FirstSecurityEventType::LOGIN_SUCCEEDED, occurredAt: $occurredAt));
        $dispatcher->dispatch(new SecondSecurityEvent(SecondSecurityEventType::TOKEN_REFUSED, ...$common, extra: ['token_hint' => 'x_ab…']));

        [$first, $success, $second] = $handler->getRecords();

        $this->assertSame(['first_security', 'first_security', 'second_security'], [$first->channel, $success->channel, $second->channel]);
        $this->assertSame([Level::Warning, Level::Info, Level::Warning], [$first->level, $success->level, $second->level]);
        $this->assertSame(['login.failed', 'login.succeeded', 'token.refused'], [$first->message, $success->message, $second->message]);

        $expected = [
            'outcome' => 'failure',
            'cause' => 'bad_credentials',
            'user_id' => '42',
            'method' => 'password',
            'firewall' => 'main',
            'ip' => '203.0.113.7',
            'user_agent' => 'Test/1.0',
            'request_id' => 'req-1',
            'occurred_at' => '2026-10-01T12:00:00+00:00',
        ];
        $this->assertSame(['type' => 'login.failed'] + $expected + ['extra' => ['a' => 1]], $first->context);
        $this->assertSame(['type' => 'token.refused'] + $expected + ['extra' => ['token_hint' => 'x_ab…']], $second->context);
        $this->assertSame(array_keys($first->context), array_keys($success->context));
        $this->assertSame('success', $success->context['outcome']);
    }
}
