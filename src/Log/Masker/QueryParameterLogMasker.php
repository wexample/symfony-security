<?php

namespace Wexample\SymfonySecurity\Log\Masker;

use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

/**
 * Masks the value of the given query parameters in every URL of a string.
 */
class QueryParameterLogMasker implements LogMaskerInterface
{
    private readonly ?string $pattern;

    /**
     * @param list<string> $names
     */
    public function __construct(array $names)
    {
        $this->pattern = $names
            ? '/([?&](?:' . implode('|', array_map(static fn (string $name) => preg_quote($name, '/'), $names)) . ')=)[^&\s"\'#]+/'
            : null;
    }

    public function mask(string $value): string
    {
        return $this->pattern ? preg_replace($this->pattern, '$1' . self::REDACTED, $value) : $value;
    }
}
