<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App;

use Symfony\Bundle\FrameworkBundle\FrameworkBundle;
use Symfony\Bundle\FrameworkBundle\Kernel\MicroKernelTrait;
use Symfony\Bundle\MonologBundle\MonologBundle;
use Symfony\Component\HttpKernel\Kernel;
use Wexample\SymfonySecurity\WexampleSymfonySecurityBundle;

class AppKernel extends Kernel
{
    use MicroKernelTrait;

    public function registerBundles(): iterable
    {
        return [
            new FrameworkBundle(),
            new MonologBundle(),
            new WexampleSymfonySecurityBundle(),
        ];
    }

    public function getProjectDir(): string
    {
        return __DIR__;
    }

    private function getConfigDir(): string
    {
        return __DIR__ . '/config';
    }
}
