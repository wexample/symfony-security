<?php

namespace Wexample\SymfonySecurity\Log\Masker;

use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

/**
 * Replaces every match of the given regular expressions by REDACTED. What
 * must stay readable around the secret goes in a lookaround:
 * `/(?<=Bearer )\S+/`.
 */
class PatternLogMasker implements LogMaskerInterface
{
    /**
     * @param list<string> $patterns
     */
    public function __construct(
        private readonly array $patterns
    ) {
    }

    public function mask(string $value): string
    {
        return $this->patterns ? preg_replace($this->patterns, self::REDACTED, $value) : $value;
    }
}
