<?php

namespace Wexample\SymfonySecurity\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Symfony\Component\Cache\Adapter\ArrayAdapter;
use Wexample\SymfonySecurity\Service\ProofOfWorkService;

class ProofOfWorkServiceTest extends TestCase
{
    private const int MAX_NUMBER = 500;

    private const int LIFETIME = 600;

    private const int MIN_DELAY = 3;

    private int $now = 1_800_000_000;

    private function service(string $secret = 'secret'): ProofOfWorkService
    {
        $test = $this;

        return new class (new ArrayAdapter(), $secret, self::MAX_NUMBER, self::LIFETIME, self::MIN_DELAY, $test) extends ProofOfWorkService {
            public function __construct($cache, $secret, $maxNumber, $lifetime, $minDelay, private readonly ProofOfWorkServiceTest $test)
            {
                parent::__construct($cache, $secret, $maxNumber, $lifetime, $minDelay);
            }

            protected function now(): int
            {
                return $this->test->getNow();
            }
        };
    }

    public function getNow(): int
    {
        return $this->now;
    }

    /**
     * What the browser does: every number until the hash matches.
     */
    private function solve(array $challenge): string
    {
        for ($number = 0; $number <= $challenge['max_number']; ++$number) {
            if (hash('sha256', $challenge['salt'] . $number) === $challenge['challenge']) {
                return ProofOfWorkService::encodeSolution($challenge, $number);
            }
        }

        $this->fail('The challenge has no solution under its max_number.');
    }

    public function testASolvedChallengeIsAcceptedOnce(): void
    {
        $service = $this->service();
        $solution = $this->solve($service->issue());
        $this->now += self::MIN_DELAY;

        $this->assertTrue($service->verify($solution));
        $this->assertFalse($service->verify($solution));
    }

    public function testASolutionSentTooSoonIsRefused(): void
    {
        $service = $this->service();
        $solution = $this->solve($service->issue());
        $this->now += self::MIN_DELAY - 1;

        $this->assertFalse($service->verify($solution));
    }

    public function testAnExpiredChallengeIsRefused(): void
    {
        $service = $this->service();
        $solution = $this->solve($service->issue());
        $this->now += self::LIFETIME + 1;

        $this->assertFalse($service->verify($solution));
    }

    public function testAWrongNumberIsRefused(): void
    {
        $service = $this->service();
        $challenge = $service->issue();
        $number = json_decode(base64_decode($this->solve($challenge)), true)['number'];
        $this->now += self::MIN_DELAY;

        $this->assertFalse($service->verify(ProofOfWorkService::encodeSolution($challenge, $number + 1)));
    }

    public function testAChallengeNotSignedHereIsRefused(): void
    {
        $solution = $this->solve($this->service('another secret')->issue());
        $this->now += self::MIN_DELAY;

        $this->assertFalse($this->service()->verify($solution));
    }

    public function testAnEasierChallengeMadeUpByTheClientIsRefused(): void
    {
        $service = $this->service();
        $challenge = ['max_number' => 1] + $service->issue();
        $this->now += self::MIN_DELAY;

        $this->assertFalse($service->verify(ProofOfWorkService::encodeSolution($challenge, 0)));
    }

    public function testGarbageIsRefused(): void
    {
        $service = $this->service();

        $this->assertFalse($service->verify(null));
        $this->assertFalse($service->verify(''));
        $this->assertFalse($service->verify('not base64 !'));
        $this->assertFalse($service->verify(base64_encode('"a string"')));
        $this->assertFalse($service->verify(base64_encode('{"salt": 1}')));
    }
}
