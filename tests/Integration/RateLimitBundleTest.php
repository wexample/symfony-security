<?php

namespace Wexample\SymfonySecurity\Tests\Integration;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Wexample\SymfonySecurity\Event\RateLimitSecurityEvent;
use Wexample\SymfonySecurity\Tests\Fixtures\App\AppKernel;

/**
 * The fixture controller allows two requests a minute to /limited, and
 * three to the whole controller, counted together under one name.
 */
class RateLimitBundleTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }

    /**
     * @return array{0: list<int>, 1: list<RateLimitSecurityEvent>}
     */
    private function hit(string ...$paths): array
    {
        $kernel = self::bootKernel();
        // The counts live in the application cache, a directory that outlives
        // the kernel; an array cache would not do, the kernel resets it
        // between two requests.
        self::getContainer()->get('cache.app')->clear();
        $events = [];
        self::getContainer()->get('event_dispatcher')->addListener(
            RateLimitSecurityEvent::class,
            static function (RateLimitSecurityEvent $event) use (&$events): void {
                $events[] = $event;
            }
        );

        $statuses = [];
        foreach ($paths as $path) {
            $request = Request::create($path, server: ['REMOTE_ADDR' => '203.0.113.7']);
            $statuses[] = $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, true)->getStatusCode();
        }

        return [$statuses, $events];
    }

    public function testRefusesBeyondTheLimit(): void
    {
        [$statuses, $events] = $this->hit('/limited', '/limited', '/limited');

        $this->assertSame([200, 200, 429], $statuses);
        $this->assertCount(1, $events);
        $this->assertSame('rate_limit.exceeded', $events[0]->type->value);
        $this->assertSame('203.0.113.7', $events[0]->ip);
        $this->assertSame('limited', $events[0]->extra['limit']);
    }

    public function testClassLimitIsSharedByName(): void
    {
        [$statuses, $events] = $this->hit('/shared', '/shared', '/limited', '/shared');

        $this->assertSame([200, 200, 200, 429], $statuses);
        $this->assertSame('fixture_shared', $events[0]->extra['limit']);
    }
}
