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
            ->end();

        return $treeBuilder;
    }
}
