<?php

namespace Wexample\SymfonySecurity\Tests\Integration;

use Monolog\Formatter\JsonFormatter;
use Monolog\Handler\TestHandler;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;
use Wexample\SymfonySecurity\Log\SecretRedactionProcessor;
use Wexample\SymfonySecurity\Tests\Fixtures\App\AppKernel;

/**
 * The bundle as an application gets it: one processor on every channel,
 * maskers from the configuration and from an application service.
 */
class SecretRedactionBundleTest extends KernelTestCase
{
    protected static function getKernelClass(): string
    {
        return AppKernel::class;
    }

    public function testEveryMaskerMasksOnEveryChannel(): void
    {
        self::bootKernel();
        $container = self::getContainer();

        foreach (['logger', 'monolog.logger.audit'] as $id) {
            /** @var LoggerInterface $logger */
            $logger = $container->get($id);
            $logger->error('Called /link?sig=s1gnatureInMessage', [
                'header' => 'Authorization: Bearer b3arerFromConfig',
                'key' => 'key_abcd0123456789ef',
                'exception' => new RuntimeException('Outer', 0, new RuntimeException('Referer /x?sig=s1gnatureInPrevious')),
            ]);
        }

        $records = $this->getHandler()->getRecords();
        $this->assertSame(['app', 'audit'], array_map(static fn ($record) => $record->channel, $records));

        $formatter = new JsonFormatter();
        $formatter->includeStacktraces();

        foreach ($records as $record) {
            $dump = $formatter->format($record);

            foreach (['s1gnatureInMessage', 'b3arerFromConfig', 'key_abcd0123456789ef', 's1gnatureInPrevious', 's1gnatureFromExtra'] as $secret) {
                $this->assertStringNotContainsString($secret, $dump, $record->channel);
            }

            $this->assertSame('Authorization: Bearer [redacted]', $record->context['header']);
            $this->assertSame('key_abcd…', $record->context['key']);
            // Added by an application processor: the redaction runs after it.
            $this->assertSame('/reset?sig=[redacted]', $record->extra['url']);
        }
    }

    public function testOneProcessorWhateverTheNumberOfMaskers(): void
    {
        self::bootKernel();
        $container = self::getContainer();

        $processors = array_filter(
            iterator_to_array($this->getProcessors($container->get('logger'))),
            static fn ($processor) => $processor instanceof SecretRedactionProcessor
        );

        $this->assertCount(1, $processors);
    }

    private function getProcessors(object $logger): iterable
    {
        yield from $logger->getProcessors();
    }

    private function getHandler(): TestHandler
    {
        return self::getContainer()->get('monolog.handler.test');
    }
}
