# symfony-security

Version: 2.1.0

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

## Table of Contents

- [Masking a secret in every log](#masking-a-secret-in-every-log)
- [Recording security facts](#recording-security-facts)
- [The request id](#the-request-id)
- [Security headers on every response](#security-headers-on-every-response)
- [Integration in the Suite](#integration-in-the-suite)
- [Dependencies](#dependencies)
- [Versioning & Compatibility Policy](#versioning--compatibility-policy)
- [License](#license)
- [About us](#about-us)
- [Migration Notes](#migration-notes)

## Integration in the Suite

This package is part of the Wexample Suite — a collection of high-quality, modular tools designed to work seamlessly together across multiple languages and environments.

### Related Packages

The suite includes packages for configuration management, file handling, prompts, and more. Each package can be used independently or as part of the integrated suite.

Visit the [Wexample Suite documentation](https://docs.wexample.com) for the complete package ecosystem.

## Dependencies

- php: >=8.5
- psr/log: ^3.0
- monolog/monolog: ^3.5
- symfony/config: ^7.4 || ^8.0
- symfony/dependency-injection: ^7.4 || ^8.0
- symfony/event-dispatcher: ^7.4 || ^8.0
- symfony/http-foundation: ^7.4 || ^8.0
- symfony/http-kernel: ^7.4 || ^8.0
- symfony/rate-limiter: ^7.4 || ^8.0
- symfony/yaml: ^7.4 || ^8.0

## Versioning & Compatibility Policy

Wexample packages follow **Semantic Versioning** (SemVer):

- **MAJOR**: Breaking changes
- **MINOR**: New features, backward compatible
- **PATCH**: Bug fixes, backward compatible

We maintain backward compatibility within major versions and provide clear migration guides for breaking changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Free to use in both personal and commercial projects.

## About us

[Wexample](https://wexample.com) stands as a cornerstone of the digital ecosystem — a collective of seasoned engineers, researchers, and creators driven by a relentless pursuit of technological excellence. More than a media platform, it has grown into a vibrant community where innovation meets craftsmanship, and where every line of code reflects a commitment to clarity, durability, and shared intelligence.

This packages suite embodies this spirit. Trusted by professionals and enthusiasts alike, it delivers a consistent, high-quality foundation for modern development — open, elegant, and battle-tested. Its reputation is built on years of collaboration, refinement, and rigorous attention to detail, making it a natural choice for those who demand both robustness and beauty in their tools.

Wexample cultivates a culture of mastery. Each package, each contribution carries the mark of a community that values precision, ethics, and innovation — a community proud to shape the future of digital craftsmanship.

## Migration Notes

When upgrading between major versions, refer to the migration guides in the documentation.

Breaking changes are clearly documented with upgrade paths and examples.
