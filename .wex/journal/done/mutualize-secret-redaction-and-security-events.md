# Shared secret redaction and security-event contract, extracted from symfony-user and symfony-api

Opened: 2026-10-01
Updated: 2026-10-01
Author: agent:sapiens

## Context

Two packages grew the same two things independently while serving one application (Sapiens):

- **Secret redaction in logs** — a Monolog processor walking every record (message, context, extra) **and the exceptions records carry**, previous ones included: `symfony-user` `src/Log/SecretRedactionProcessor.php` (link signatures, commit `e9ed96b`) and `symfony-api` (machine tokens replaced by their hint, commit `70dbbe5`). The `symfony-user` agent proposed sharing the walk; the owner chose this package over `symfony-helpers`, which is already too large.
- **A security-event contract** — `SecurityEvent` in `symfony-user` and `MachineSecurityEvent` in `symfony-api` carry the same shape (stable type, cause, actor/subject identifier, IP, user agent, firewall, request id, UTC time, extra) and are each written to their own Monolog channel. A future audit package should listen to one contract, not two.

## Task

1. **Redaction**: an abstract processor (or one processor with registered maskers) owning the record walk, exceptions included; each package contributes only *what* to mask (a pattern, a callback). Applications can register their own maskers. Same guarantee as today: nothing a formatter reads escapes the walk.
2. **Security event**: one base event class (or interface) with the common fields and a request-id resolver (`X-Request-Id` or generated); `SecurityEvent` and `MachineSecurityEvent` extend it, keeping their types and channels. One default subscriber writing any of them to its channel.
3. Migrate `symfony-user` and `symfony-api` onto it, without changing their behaviour, channel names, event types or configuration — their applications must see no difference. Their existing "search every record of every channel for each secret" tests stay green, untouched.
4. Keep this package small: no dependency on `symfony-user` or `symfony-api`; they depend on it.

## Tests

- A masker registered by a package or an application masks in message, context, extra and carried exceptions (with a previous one).
- Both events written through the shared subscriber to their own channel, with identical common fields.
- `symfony-user` and `symfony-api` suites green after migration.

## Work log

- Baselines before any change: `symfony-user` 98 tests / 1813 assertions, `symfony-api` 44 / 307, run in `wex-php85-intl` (the design-system container was not running).
- Chose the abstract processor over "one processor with registered maskers": a registry needs a bundle, and every application installing `symfony-user` or `symfony-api` would then have to register `WexampleSymfonySecurityBundle` or break. The package ships no bundle and no configuration.
- Same reason for the subscriber: an abstract one, extended in each package by a class that names its channel (`#[WithMonologChannel]`, which is also what creates the channel) and its event. The class names and service ids applications may reference stay.
- Mutation-checked the walk: removing the previous-exception loop, the key masking, the object reading or the `Stringable` reading each fails a test.
- Suites after migration: `symfony-security` 9 / 50, `symfony-user` 98 / 1813, `symfony-api` 44 / 307. Their existing secret-search tests were not touched.

## Reply

1. **Verdict**: real gap, implemented, no demo. Commits: `symfony-security` `af1c50f`, `symfony-user` `2b55774`, `symfony-api` `dff2317`.

2. **What the package does now** — no bundle, no option:
   - `Log\AbstractSecretRedactionProcessor`: owns the walk (message, context, extra, nested arrays, **string keys**, carried exceptions with their previous ones, rewritten in place); a subclass implements `mask(string): string`, helped by `maskQueryParameters($value, $names)`. An application masks its own secrets by extending it with `#[AsMonologProcessor]`. `SecretRedactionProcessor` (user) and `MachineTokenRedactionProcessor` (api) keep their names and only say what to mask.
   - `Event\AbstractSecurityEvent` (the common fields, `toArray()` unchanged) + `Interface\SecurityEventTypeInterface` (`BackedEnum` + `isFailure()`), implemented by `SecurityEventType` and `MachineSecurityEventType`. Each event narrows its type in its constructor and is still dispatched under its own class name, so existing listeners keep working.
   - `EventSubscriber\AbstractSecurityEventLogSubscriber`: writes any of them (`type` as message, `toArray()` as context, `warning` on failure). `SecurityJournalLogSubscriber` / `MachineSecurityJournalLogSubscriber` keep their classes and channels (`user_security`, `machine_security`).
   - `Helper\RequestIdHelper::resolve($request)`: `X-Request-Id` or a generated id, stored once per request.
   - Divergence from the request: "one default subscriber" is one abstract subscriber plus two thin subclasses, and redaction runs one walk per package rather than one walk with registered maskers. A single shared service would need a bundle, as explained in the work log.

3. **Found and fixed on the way**:
   - The two packages each generated their own request id, so a request that produced a user event and a machine event logged two ids. They now share one, and so does the `api_batch` record, which copied the raw header and logged `null` without it.
   - `X-Request-Id` was copied verbatim from the client into every security record. A value with anything other than visible ASCII, or longer than 128 characters, is now replaced by a generated id. Valid ids are unchanged.
   - The walk did not cover objects: a `Stringable` or `JsonSerializable` object, or an object with public properties, was printed by the formatter without masking (a `Request` in the context prints its `Authorization` header). It is now read the way the formatter reads it, and replaced by `[Class => masked reading]` only when it held a secret.
   - Checked through both suites' HTTP-level tests, **not** in a real app over HTTP: the design-system container was down.
   - Left out of the commits: `symfony-security/composer.lock` (new, untracked) and `symfony-api/composer.lock` (already untracked before; it now has the new entry). Versions were not bumped. `symfony-user/composer.lock` was committed: besides the new entry, every sibling path package's reference moved to its current state.

4. **Notice for the application agent**

> `wexample/symfony-user` and `wexample/symfony-api` now depend on `wexample/symfony-security` (a plain library: no bundle to register, nothing to configure). A `composer update` of either brings it.
>
> Nothing changes in the journals: same channels (`user_security`, `machine_security`), same event classes and types, same record shape. Two differences:
> - within one request, every journal (user, machine token, `api_batch`) carries the **same** `request_id`;
> - an `X-Request-Id` holding anything but visible ASCII, or longer than 128 characters, is ignored and replaced by a generated id. If a proxy sets this header, check that its ids fit.
>
> To mask a secret of the application in every log, extend `Wexample\SymfonySecurity\Log\AbstractSecretRedactionProcessor`, implement `mask()`, and add `#[AsMonologProcessor]`. Exceptions, nested arrays and objects in the context are handled by the parent.
>
> To journal the application's own security facts in the same shape, extend `AbstractSecurityEvent` with an enum implementing `SecurityEventTypeInterface`, and `AbstractSecurityEventLogSubscriber` with `#[WithMonologChannel('<app>_security')]`. Facts already covered by `symfony-user` stay on `SecurityJournalService::record()`.
>
> Still open: a processor registered on a single handler (not on the logger) runs after the redaction, so what it adds is not masked. Register log processors on the logger.
