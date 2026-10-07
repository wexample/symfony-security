<?php

namespace Wexample\SymfonySecurity\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Wexample\SymfonySecurity\EventSubscriber\SecurityHeadersSubscriber;
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

        $container->setDefinition(
            SecurityHeadersSubscriber::class,
            (new Definition(SecurityHeadersSubscriber::class, [$this->buildHeaders($config['headers'])]))
                ->addTag('kernel.event_subscriber')
        );

        (new YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config')))->load('services.yaml');
    }

    /**
     * @param array<string, string|null> $config
     * @return array<string, string> header name => value, the ones left out removed
     */
    private function buildHeaders(array $config): array
    {
        $names = [
            'strict_transport_security' => 'Strict-Transport-Security',
            'content_type_options' => 'X-Content-Type-Options',
            'frame_options' => 'X-Frame-Options',
            'referrer_policy' => 'Referrer-Policy',
            'content_security_policy' => 'Content-Security-Policy',
        ];

        $headers = [];
        foreach ($config as $key => $value) {
            if (null !== $value) {
                $headers[$names[$key]] = $value;
            }
        }

        return $headers;
    }
}
