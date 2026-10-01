<?php

namespace Wexample\SymfonySecurity\Log;

use DateTimeInterface;
use Error;
use Exception;
use JsonSerializable;
use Monolog\LogRecord;
use ReflectionProperty;
use Stringable;
use Throwable;

/**
 * Walks everything a formatter reads of a log record — message, context,
 * extra, array keys included — and hands each string to mask(): a package
 * only says what its secret looks like.
 *
 * An exception carried by a record is rewritten in place, with its previous
 * ones: the formatter reads its message after this processor, and a 404
 * quotes the referer. Any other object is read the way the formatter reads
 * it — jsonSerialize(), __toString(), public properties — and replaced by
 * that masked reading, only when it held a secret.
 *
 * A subclass is registered with #[AsMonologProcessor], so that it runs on
 * every channel.
 */
abstract class AbstractSecretRedactionProcessor
{
    public const string REDACTED = '[redacted]';

    /**
     * Returns the string with every secret it holds masked.
     */
    abstract protected function mask(string $value): string;

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(
            message: $this->redact($record->message),
            context: $this->redact($record->context),
            extra: $this->redact($record->extra),
        );
    }

    /**
     * Masks the value of the given query parameters in every URL of the string.
     *
     * @param list<string> $names
     */
    protected function maskQueryParameters(string $value, array $names): string
    {
        return preg_replace(
            '/([?&](?:' . implode('|', array_map(static fn (string $name) => preg_quote($name, '/'), $names)) . ')=)[^&\s"\'#]+/',
            '$1' . static::REDACTED,
            $value
        );
    }

    private function redact(mixed $value): mixed
    {
        if (is_string($value)) {
            return $this->mask($value);
        }

        if (is_array($value)) {
            $redacted = [];

            foreach ($value as $key => $item) {
                $redacted[is_string($key) ? $this->mask($key) : $key] = $this->redact($item);
            }

            return $redacted;
        }

        if ($value instanceof Throwable) {
            for ($exception = $value; null !== $exception; $exception = $exception->getPrevious()) {
                $message = $this->mask($exception->getMessage());

                if ($message !== $exception->getMessage()) {
                    $property = new ReflectionProperty($exception instanceof Exception ? Exception::class : Error::class, 'message');
                    $property->setValue($exception, $message);
                }
            }

            return $value;
        }

        if (is_object($value) && ! $value instanceof DateTimeInterface) {
            $reading = $this->read($value);
            $redacted = $this->redact($reading);

            // The formatter's own shape, so a masked object reads as it would have.
            return $redacted === $reading ? $value : [$value::class => $redacted];
        }

        return $value;
    }

    /**
     * What Monolog's NormalizerFormatter writes of an object.
     */
    private function read(object $value): mixed
    {
        if ($value instanceof Stringable && ! $value instanceof JsonSerializable) {
            try {
                return (string) $value;
            } catch (Throwable) {
            }
        }

        return json_decode(
            (string) json_encode($value, JSON_PARTIAL_OUTPUT_ON_ERROR | JSON_INVALID_UTF8_SUBSTITUTE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            true
        );
    }
}
