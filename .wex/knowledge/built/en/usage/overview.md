## Masking a secret in every log

One processor, `SecretRedactionProcessor`, is registered on every channel, last of the logger's processors (`priority: -1024`), so what the others add — a URL in `extra` — is walked too. It walks each record once and hands every string to every masker, in the order of their tag priority.

A masker says what one kind of secret looks like. Three ways to declare one:

- in the configuration, for a query parameter or a pattern: see `readme/installation`;
- as a service of `QueryParameterLogMasker` or `PatternLogMasker`, from a package's `services.yaml` — `symfony-user` masks its link signatures this way:

```yaml
wexample_symfony_user.log_masker.link_signature:
    class: Wexample\SymfonySecurity\Log\Masker\QueryParameterLogMasker
    arguments: [['hash']]
```

- as a class implementing `LogMaskerInterface`, when the secret needs code — `symfony-api`'s `MachineTokenLogMasker` replaces a token by its hint. Autoconfiguration tags it:

```php
use Wexample\SymfonySecurity\Interface\LogMaskerInterface;

class PartnerKeyLogMasker implements LogMaskerInterface
{
    public function mask(string $value): string
    {
        return preg_replace('/pk_([0-9a-f]{4})[0-9a-f]{28}/', 'pk_$1…', $value);
    }
}
```

What the processor walks, so that a masker only ever sees strings:

- the message, the context, the extra, nested arrays and their string keys;
- an exception carried anywhere in the record, and its previous ones: their message is rewritten in place, since the formatter reads it after the processors — and so does any handler holding the object;
- any other object, read as Monolog's formatter reads it — `jsonSerialize()`, else `__toString()`, else its public properties —, replaced by `[Class => masked reading]` when it held a secret, left untouched otherwise. Dates are left alone.

Not covered: a processor registered on a single handler runs after the logger's processors, so what it adds is not walked; a formatter reading something else than the record.

## Recording security facts

A package or an application declares its codes as an enum implementing `SecurityEventTypeInterface` (`isFailure()` sets the outcome and the log level), an event extending `AbstractSecurityEvent` that narrows the type, and a log subscriber naming the channel:

```php
enum BillingSecurityEventType: string implements SecurityEventTypeInterface
{
    case CARD_ADDED = 'billing.card_added';
    case CARD_REFUSED = 'billing.card_refused';

    public function isFailure(): bool
    {
        return self::CARD_REFUSED === $this;
    }
}

class BillingSecurityEvent extends AbstractSecurityEvent
{
    public function __construct(BillingSecurityEventType $type, mixed ...$arguments)
    {
        parent::__construct($type, ...$arguments);
    }
}

#[WithMonologChannel('billing_security')]
class BillingSecurityLogSubscriber extends AbstractSecurityEventLogSubscriber
{
    public static function getSubscribedEvents(): array
    {
        return [BillingSecurityEvent::class => 'onSecurityEvent'];
    }
}
```

The subscriber stays one small class per package: the `#[WithMonologChannel]` attribute is what creates the channel and hands it the right logger, and the event is dispatched under its own class name, so existing listeners keep their event. A recorder of every security fact — an audit package — listens to each class and reads them through `AbstractSecurityEvent::toArray()`:

```
type, outcome (success|failure), cause, user_id, method, firewall, ip, user_agent, request_id, occurred_at (UTC, ATOM), extra
```

The subscriber writes `type` as the message and that array as the context, at `warning` for a failure and `info` otherwise. The event never holds a secret: name a token by a hint, an unknown identifier by a fingerprint, in `extra`.

## The request id

`RequestIdHelper::resolve($requestStack->getMainRequest())` returns the `X-Request-Id` header given by a proxy, or an id of 16 hex characters generated once per request, and the same to every package asking during that request — the security journals of `symfony-user` and `symfony-api`, the batch log of `symfony-api`. A header holding anything but visible ASCII, or longer than 128 characters, is replaced by a generated id: it comes from the client and lands in every security record. `null` outside a request.

## Security headers on every response

`SecurityHeadersSubscriber` adds these headers to every main response, error pages included:

```
Strict-Transport-Security: max-age=31536000; includeSubDomains   (over HTTPS only)
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
```

A header the response already carries is kept: a page that must be framed elsewhere sets its own `X-Frame-Options` on its response. `Content-Security-Policy` is off until the application writes one — a policy depends on its own scripts and styles. Each value is changed or left out in the configuration: see `readme/installation`.

Before switching an existing host to HTTPS only, remember that a browser keeps `Strict-Transport-Security` for `max-age` seconds after reading it, subdomains included: shorten it, or drop `includeSubDomains`, while a subdomain still serves plain HTTP.

## A captcha nobody solves by hand

`ProofOfWorkService` makes the browser pay for a submission with work instead of a puzzle. `issue()` draws a challenge — the SHA-256 of a random salt and a number below `max_number` — and signs it with the kernel secret. The browser tries every number until the hash matches and sends back the challenge with the number. `verify()` checks, in one hash:

- the signature, so a challenge made up by the client, easier, is refused;
- its age: younger than `min_delay` (a form filled in by a program) or older than `lifetime` is refused;
- the number;
- that it was not used yet: a solved salt is kept in `cache.app` for the lifetime, so one solution sends one submission, on whichever worker.

Nothing is stored when a challenge is issued, so a page drawn by one worker is checked by another. At the default `max_number` (100 000) the browser takes a few hundred milliseconds; a bot sending thousands of submissions pays thousands of times. Nothing reaches a third party.

```yaml
wexample_symfony_security:
  proof_of_work:
    max_number: 100000   # the work, half of it on average
    lifetime: 3600       # seconds to fill the form in
    min_delay: 3         # seconds below which a person cannot have filled it in
```

A form uses it through symfony-forms' `ProofOfWorkInputType`, which draws the challenge, solves it in the browser and checks it on submission.
