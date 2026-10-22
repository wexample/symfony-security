<?php

namespace Wexample\SymfonySecurity\Tests\Integration;

use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Symfony\Component\HttpFoundation\Request;
use Wexample\SymfonySecurity\Tests\Fixtures\App\AppKernel;

/**
 * The headers as an application gets them: the defaults, one overridden,
 * one left out — the fixture configuration sets frame_options and drops
 * referrer_policy.
 */
class SecurityHeadersBundleTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }

    public function testTheConfiguredHeadersReachTheResponse(): void
    {
        $response = self::bootKernel()->handle(Request::create('https://localhost/missing'));

        $this->assertSame('max-age=31536000; includeSubDomains', $response->headers->get('Strict-Transport-Security'));
        $this->assertSame('nosniff', $response->headers->get('X-Content-Type-Options'));
        $this->assertSame('DENY', $response->headers->get('X-Frame-Options'));
        $this->assertFalse($response->headers->has('Referrer-Policy'));
        $this->assertFalse($response->headers->has('Content-Security-Policy'));
    }
}
