<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use Error;
use JsonSerializable;
use LogicException;
use Monolog\Formatter\JsonFormatter;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\TestHandler;
use Monolog\Logger;
use Monolog\LogRecord;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use stdClass;
use Wexample\SymfonySecurity\Tests\Fixtures\Log\ApiKeyRedactionProcessor;
use Wexample\SymfonySecurity\Tests\Fixtures\Log\QueryTokenRedactionProcessor;

/**
 * Every place a formatter reads, checked on what the formatters actually
 * write: a secret found in a formatted record is a leak, wherever it sits.
 */
class SecretRedactionProcessorTest extends TestCase
{
    private const string TOKEN = 'tok3nS3cr3tValue';

    private const string SIGNATURE = 'sig5ecretValue';

    private const string API_KEY = 'key_abcd0123456789ef';

    private TestHandler $handler;

    private Logger $logger;

    protected function setUp(): void
    {
        $this->handler = new TestHandler();
        // One processor of a package, one of an application.
        $this->logger = new Logger('app', [$this->handler], [
            new QueryTokenRedactionProcessor(),
            new ApiKeyRedactionProcessor(),
        ]);
    }

    public function testMessageContextAndExtraAreMasked(): void
    {
        $this->logger->pushProcessor(static fn (LogRecord $record) => $record->with(
            extra: ['url' => '/link?sig=' . self::SIGNATURE . '&lang=en']
        ));
        $this->logger->info('Matched route for /login?token=' . self::TOKEN, [
            'request_uri' => 'http://localhost/login?a=1&token=' . self::TOKEN . '#top',
            'nested' => ['header' => 'Authorization: ' . self::API_KEY],
            '/?token=' . self::TOKEN => 'as a key',
            'count' => 3,
        ]);

        $this->assertNoSecret();
        $record = $this->handler->getRecords()[0];
        $this->assertSame('Matched route for /login?token=[redacted]', $record->message);
        $this->assertSame('http://localhost/login?a=1&token=[redacted]#top', $record->context['request_uri']);
        $this->assertSame('Authorization: key_abcd…', $record->context['nested']['header']);
        $this->assertSame(3, $record->context['count']);
        // Added by a processor pushed later, which runs first: masked all the same.
        $this->assertSame('/link?sig=[redacted]&lang=en', $record->extra['url']);
    }

    public function testCarriedExceptionsAreMaskedWithTheirPreviousOnes(): void
    {
        $previous = new Error('Referer /reset?sig=' . self::SIGNATURE);
        $exception = new RuntimeException('No route found for "GET /x?token=' . self::TOKEN . '"', 0, $previous);

        $this->logger->error('Uncaught', ['exception' => $exception]);

        $this->assertNoSecret();
        // Rewritten in place: a handler holding the object reads it masked too.
        $this->assertSame('No route found for "GET /x?token=[redacted]"', $exception->getMessage());
        $this->assertSame('Referer /reset?sig=[redacted]', $previous->getMessage());
    }

    public function testObjectsAreReadAsTheFormatterReadsThem(): void
    {
        $stringable = new class (self::API_KEY) {
            public function __construct(private readonly string $key)
            {
            }

            public function __toString(): string
            {
                return 'Bearer ' . $this->key;
            }
        };
        $serializable = new class (self::TOKEN) implements JsonSerializable {
            public function __construct(private readonly string $token)
            {
            }

            public function jsonSerialize(): array
            {
                return ['url' => '/?token=' . $this->token];
            }
        };
        $public = new stdClass();
        $public->link = '/?sig=' . self::SIGNATURE;
        $clean = new stdClass();
        $clean->name = 'nothing to hide';

        $this->logger->info('Objects', compact('stringable', 'serializable', 'public', 'clean'));

        $this->assertNoSecret();
        $context = $this->handler->getRecords()[0]->context;
        $this->assertSame([$stringable::class => 'Bearer key_abcd…'], $context['stringable']);
        $this->assertSame([stdClass::class => ['link' => '/?sig=[redacted]']], $context['public']);
        // Nothing to mask: the object is left as it was.
        $this->assertSame($clean, $context['clean']);
    }

    public function testAFailingStringableIsReadByItsProperties(): void
    {
        $object = new class (self::TOKEN) {
            public function __construct(public readonly string $url)
            {
            }

            public function __toString(): string
            {
                throw new LogicException('Not printable');
            }
        };
        $object = new $object('/?token=' . self::TOKEN);

        $this->logger->info('Object', ['object' => $object]);

        $this->assertNoSecret();
    }

    private function assertNoSecret(): void
    {
        $line = new LineFormatter(allowInlineLineBreaks: true);
        $line->includeStacktraces();
        $json = new JsonFormatter();
        $json->includeStacktraces();

        foreach ($this->handler->getRecords() as $record) {
            foreach ([$line->format($record), $json->format($record)] as $dump) {
                foreach ([self::TOKEN, self::SIGNATURE, self::API_KEY] as $secret) {
                    $this->assertStringNotContainsString($secret, $dump);
                }
            }
        }
    }
}
