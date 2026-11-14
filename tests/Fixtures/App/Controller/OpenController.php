<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App\Controller;

use RuntimeException;
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

    /**
     * Fails, for the error page to be rendered by a sub-request of the same path.
     */
    #[Route('/open/boom', name: 'open_boom')]
    public function boom(): Response
    {
        throw new RuntimeException('Fixture failure.');
    }
}
