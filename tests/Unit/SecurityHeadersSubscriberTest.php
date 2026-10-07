<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Wexample\SymfonySecurity\EventSubscriber\SecurityHeadersSubscriber;

class SecurityHeadersSubscriberTest extends TestCase
{
    private const array HEADERS = [
        'Strict-Transport-Security' => 'max-age=31536000',
        'X-Frame-Options' => 'SAMEORIGIN',
    ];

    public function testEveryHeaderIsSentOverHttps(): void
    {
        $response = $this->respond(Request::create('https://example.com/'));

        $this->assertSame('max-age=31536000', $response->headers->get('Strict-Transport-Security'));
        $this->assertSame('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
    }

    public function testStrictTransportSecurityIsLeftOutOverHttp(): void
    {
        $response = $this->respond(Request::create('http://example.com/'));

        $this->assertFalse($response->headers->has('Strict-Transport-Security'));
        $this->assertSame('SAMEORIGIN', $response->headers->get('X-Frame-Options'));
    }

    public function testAHeaderSetByTheResponseIsKept(): void
    {
        $response = new Response();
        $response->headers->set('X-Frame-Options', 'DENY');

        $this->respond(Request::create('https://example.com/'), $response);

        $this->assertSame('DENY', $response->headers->get('X-Frame-Options'));
    }

    public function testASubRequestIsLeftAlone(): void
    {
        $response = $this->respond(Request::create('https://example.com/'), type: HttpKernelInterface::SUB_REQUEST);

        $this->assertFalse($response->headers->has('X-Frame-Options'));
    }

    private function respond(
        Request $request,
        Response $response = new Response(),
        int $type = HttpKernelInterface::MAIN_REQUEST
    ): Response {
        (new SecurityHeadersSubscriber(self::HEADERS))->onResponse(
            new ResponseEvent($this->createStub(HttpKernelInterface::class), $request, $type, $response)
        );

        return $response;
    }
}
