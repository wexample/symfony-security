<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use LogicException;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Wexample\SymfonySecurity\Helper\SecurityBundleHelper;
use Wexample\SymfonySecurity\WexampleSymfonySecurityBundle;

class SecurityBundleHelperTest extends TestCase
{
    public function testAMissingBundleFailsTheBuild(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('SomeBundle requires ' . WexampleSymfonySecurityBundle::class);

        SecurityBundleHelper::assertRegistered(new ContainerBuilder(), 'SomeBundle');
    }

    public function testARegisteredBundlePasses(): void
    {
        $container = new ContainerBuilder();
        $container->registerExtension((new WexampleSymfonySecurityBundle())->getContainerExtension());

        SecurityBundleHelper::assertRegistered($container, 'SomeBundle');
        $this->addToAssertionCount(1);
    }
}
