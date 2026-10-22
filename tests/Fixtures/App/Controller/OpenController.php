<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App\Controller;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * No #[RateLimit] here: what limits it comes from the configuration.
 */
class OpenController
{
    #[Route('/open', name: 'open')]
    public function open(): Response
    {
        return new Response('ok');
    }

    #[Route('/open/mail', name: 'open_mail')]
    public function mail(): Response
    {
        return new Response('ok');
    }
}
