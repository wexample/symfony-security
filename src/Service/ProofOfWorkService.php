<?php

namespace Wexample\SymfonySecurity\Service;

use Psr\Cache\CacheItemPoolInterface;

/**
 * A captcha nobody has to solve by hand: the browser pays for a submission
 * with a few hundred milliseconds of work, which a person never notices and
 * which a bot sending thousands of them pays thousands of times.
 *
 * The challenge is the hash of a salt and a number kept secret, the number
 * drawn below `max_number`; the browser finds it by trying every number, the
 * server checks it with one hash. Nothing is stored when it is issued: the
 * challenge carries its own signature, made with the kernel secret, so a
 * page served by one worker is checked by another. What is stored is the
 * salt of a challenge once solved, for its lifetime, so that one solution
 * sends one submission.
 *
 * A submission arriving sooner than `min_delay` after its challenge was
 * issued is refused as well: nobody reads a form and fills it in that fast.
 */
class ProofOfWorkService
{
    public const string ALGORITHM = 'SHA-256';

    private const string CACHE_PREFIX = 'wexample_symfony_security.proof_of_work.';

    public function __construct(
        private readonly CacheItemPoolInterface $cache,
        private readonly string $secret,
        private readonly int $maxNumber,
        private readonly int $lifetime,
        private readonly int $minDelay,
    ) {
    }

    /**
     * @return array{algorithm: string, salt: string, challenge: string, max_number: int, issued: int, signature: string}
     */
    public function issue(): array
    {
        $salt = bin2hex(random_bytes(12));
        $challenge = [
            'algorithm' => self::ALGORITHM,
            'salt' => $salt,
            'challenge' => hash('sha256', $salt . random_int(0, $this->maxNumber)),
            'max_number' => $this->maxNumber,
            'issued' => $this->now(),
        ];

        return $challenge + ['signature' => $this->sign($challenge)];
    }

    /**
     * The solution the browser sends: the challenge it was given, and the
     * number it found, as base64-encoded JSON.
     */
    public static function encodeSolution(array $challenge, int $number): string
    {
        return base64_encode(json_encode($challenge + ['number' => $number]));
    }

    /**
     * True once per challenge, signed here, neither too young nor expired,
     * whose number is the one hashed. Consumes the challenge.
     */
    public function verify(?string $solution): bool
    {
        $data = json_decode(base64_decode((string) $solution, true) ?: '', true);

        if (! is_array($data)) {
            return false;
        }

        foreach (['salt', 'challenge', 'signature'] as $key) {
            if (! is_string($data[$key] ?? null)) {
                return false;
            }
        }

        foreach (['max_number', 'issued', 'number'] as $key) {
            if (! is_int($data[$key] ?? null)) {
                return false;
            }
        }

        $challenge = [
            'algorithm' => self::ALGORITHM,
            'salt' => $data['salt'],
            'challenge' => $data['challenge'],
            'max_number' => $data['max_number'],
            'issued' => $data['issued'],
        ];
        $age = $this->now() - $data['issued'];

        if (! hash_equals($this->sign($challenge), $data['signature'])
            || $age < $this->minDelay
            || $age > $this->lifetime
            || ! hash_equals($data['challenge'], hash('sha256', $data['salt'] . $data['number']))) {
            return false;
        }

        // Signed here, so the salt is ours and safe to name a cache entry.
        $item = $this->cache->getItem(self::CACHE_PREFIX . $data['salt']);

        if ($item->isHit()) {
            return false;
        }

        $this->cache->save($item->set(true)->expiresAfter($this->lifetime));

        return true;
    }

    protected function now(): int
    {
        return time();
    }

    private function sign(array $challenge): string
    {
        return hash_hmac('sha256', json_encode($challenge), $this->secret);
    }
}
