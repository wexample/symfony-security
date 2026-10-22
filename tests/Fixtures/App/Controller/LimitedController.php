<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Wexample\SymfonySecurity\Attribute\RateLimit;

#[RateLimit(3, '1 minute', name: 'fixture_shared')]
class LimitedController
{
    #[Route('/limited', name: 'limited')]
    #[RateLimit(2, '1 minute')]
    public function limited(): Response
    {
        return new Response('ok');
    }

    #[Route('/shared', name: 'shared')]
    public function shared(): Response
    {
        return new Response('ok');
    }
}
