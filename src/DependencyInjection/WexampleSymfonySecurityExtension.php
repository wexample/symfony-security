<?php

namespace Wexample\SymfonySecurity\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Wexample\SymfonyHelpers\DependencyInjection\AbstractWexampleSymfonyExtension;
use Wexample\SymfonySecurity\Interface\LogMaskerInterface;
use Wexample\SymfonySecurity\Log\Masker\PatternLogMasker;
use Wexample\SymfonySecurity\Log\Masker\QueryParameterLogMasker;

class WexampleSymfonySecurityExtension extends AbstractWexampleSymfonyExtension
{
    public function load(
        array $configs,
        ContainerBuilder $container
    ): void {
        $config = $this->processConfiguration(new Configuration(), $configs);

        $container
            ->registerForAutoconfiguration(LogMaskerInterface::class)
            ->addTag(LogMaskerInterface::TAG);

        foreach ([
            'query_parameters' => QueryParameterLogMasker::class,
            'patterns' => PatternLogMasker::class,
        ] as $key => $class) {
            if ($config['redaction'][$key]) {
                $container->setDefinition(
                    'wexample_symfony_security.log_masker.' . $key,
                    (new Definition($class, [$config['redaction'][$key]]))->addTag(LogMaskerInterface::TAG)
                );
            }
        }

        $this->loadConfig(
            __DIR__,
            $container
        );
    }
}
