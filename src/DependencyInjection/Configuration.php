<?php

namespace Wexample\SymfonySecurity\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('wexample_symfony_security');

        $treeBuilder->getRootNode()
            ->children()
                ->arrayNode('redaction')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->arrayNode('query_parameters')
                            ->info('Query parameters whose value is masked in every log record, as in "/link?token=[redacted]".')
                            ->scalarPrototype()->end()
                            ->defaultValue([])
                        ->end()
                        ->arrayNode('patterns')
                            ->info('Regular expressions whose matches are masked in every log record. Keep what must stay readable in a lookaround: "/(?<=Bearer )\S+/".')
                            ->scalarPrototype()
                                ->validate()
                                    ->ifTrue(static fn (string $pattern) => false === @preg_match($pattern, ''))
                                    ->thenInvalid('%s is not a valid regular expression.')
                                ->end()
                            ->end()
                            ->defaultValue([])
                        ->end()
                    ->end()
                ->end()
                ->arrayNode('headers')
                    ->info('Security headers added to every main response that does not set them already; null leaves one out.')
                    ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('strict_transport_security')
                            ->info('Sent over HTTPS only. Once a browser has read it, it refuses plain HTTP on the host for max-age seconds.')
                            ->defaultValue('max-age=31536000; includeSubDomains')
                        ->end()
                        ->scalarNode('content_type_options')
                            ->defaultValue('nosniff')
                        ->end()
                        ->scalarNode('frame_options')
                            ->info('Who may show the pages in a frame. DENY when no page of the application is ever framed.')
                            ->defaultValue('SAMEORIGIN')
                        ->end()
                        ->scalarNode('referrer_policy')
                            ->defaultValue('strict-origin-when-cross-origin')
                        ->end()
                        ->scalarNode('content_security_policy')
                            ->info('Off by default: a policy is written against the scripts and styles of the application, not guessed.')
                            ->defaultNull()
                        ->end()
                    ->end()
                ->end()
            ->end();

        return $treeBuilder;
    }
}
