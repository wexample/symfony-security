<?php

namespace Wexample\SymfonySecurity\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Wexample\SymfonySecurity\Interface\LogMaskerInterface;
use Wexample\SymfonySecurity\Log\Masker\PatternLogMasker;
use Wexample\SymfonySecurity\Log\Masker\QueryParameterLogMasker;

class WexampleSymfonySecurityExtension extends Extension
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

        (new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config')))->load('services.yaml');
    }
}
