<?php

namespace Wexample\SymfonySecurity\Log;

use DateTimeInterface;
use Error;
use Exception;
use JsonSerializable;
use Monolog\LogRecord;
use ReflectionProperty;
use Stringable;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Throwable;
use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

/**
 * Walks, once, everything a formatter reads of a log record — message,
 * context, extra, array keys included — and hands each string to every
 * masker: the packages and the application only say what their secrets look
 * like.
 *
 * An exception carried by a record is rewritten in place, with its previous
 * ones: the formatter reads its message after this processor, and a 404
 * quotes the referer. Any other object is read the way the formatter reads
 * it — jsonSerialize(), __toString(), public properties — and replaced by
 * that masked reading, only when it held a secret.
 *
 * Registered on every channel, after the other processors of the logger, so
 * that what they add is walked too.
 */
class SecretRedactionProcessor
{
    /**
     * @param iterable<LogMaskerInterface> $maskers
     */
    public function __construct(
        #[AutowireIterator(LogMaskerInterface::TAG)]
        private readonly iterable $maskers,
    ) {
    }

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(
            message: $this->redact($record->message),
            context: $this->redact($record->context),
            extra: $this->redact($record->extra),
        );
    }

    private function mask(string $value): string
    {
        foreach ($this->maskers as $masker) {
            $value = $masker->mask($value);
        }

        return $value;
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
