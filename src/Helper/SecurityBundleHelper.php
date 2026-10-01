<?php

namespace Wexample\SymfonySecurity\Helper;

use LogicException;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Wexample\SymfonySecurity\WexampleSymfonySecurityBundle;

/**
 * For the bundles relying on this one: without it, their secrets would reach
 * the logs unmasked, silently.
 */
class SecurityBundleHelper
{
    /**
     * Called from a bundle's build(), once every extension is registered.
     */
    public static function assertRegistered(ContainerBuilder $container, string $requiredBy): void
    {
        if (! $container->hasExtension('wexample_symfony_security')) {
            throw new LogicException(sprintf(
                '%s requires %s, which masks its secrets in the logs: add it to config/bundles.php.',
                $requiredBy,
                WexampleSymfonySecurityBundle::class
            ));
        }
    }
}
