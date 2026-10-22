<?php

namespace Wexample\SymfonySecurity\Interface;

/**
 * Says what one kind of secret looks like in a string. A service implementing
 * it is tagged by autoconfiguration, and SecretRedactionProcessor hands it
 * every string of every log record; the tag's `priority` orders the maskers.
 */
interface LogMaskerInterface
{
    public const string TAG = 'wexample_symfony_security.log_masker';

    public const string REDACTED = '[redacted]';

    /**
     * Returns the string with every secret it holds masked.
     */
    public function mask(string $value): string;
}
