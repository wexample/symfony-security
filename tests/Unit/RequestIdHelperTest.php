<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Wexample\SymfonySecurity\Helper\RequestIdHelper;

class RequestIdHelperTest extends TestCase
{
    public function testTheProxyIdIsKept(): void
    {
        $request = new Request(server: ['HTTP_X_REQUEST_ID' => 'Root=1-67891233-abcdef012345678912345678']);

        $this->assertSame('Root=1-67891233-abcdef012345678912345678', RequestIdHelper::resolve($request));
    }

    public function testAnIdIsGeneratedOnceForTheRequest(): void
    {
        $request = new Request();
        $id = RequestIdHelper::resolve($request);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $id);
        $this->assertSame($id, RequestIdHelper::resolve($request));
        $this->assertNotSame($id, RequestIdHelper::resolve(new Request()));
    }

    public function testAnUnfitHeaderIsReplaced(): void
    {
        foreach (["abc\nlogin.succeeded user_id=1", 'with space', str_repeat('a', 129), ''] as $header) {
            $request = new Request();
            $request->headers->set(RequestIdHelper::HEADER, $header);

            $this->assertMatchesRegularExpression('/^[0-9a-f]{16}$/', RequestIdHelper::resolve($request), $header);
        }
    }

    public function testNoRequestNoId(): void
    {
        $this->assertNull(RequestIdHelper::resolve(null));
    }
}
