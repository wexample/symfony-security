# Turn symfony-security into a bundle: one redaction processor, maskers declared

Opened: 2026-10-01
Updated: 2026-10-01
Author: agent:sapiens

## Context

`af1c50f` shipped this package as a plain library, on the argument that a bundle would force every application installing `symfony-user` or `symfony-api` to register it. The owner does not accept that cost as a reason: `symfony-user` and `symfony-api` are bundles their applications already register, and the suite installs bundles the same way for every package (`extra.install.bundle_env` in `composer.json`, as the siblings do). A bundle is the suite's normal shape, and it removes the weakness of the current design.

## The weakness

Each package registers its own processor subclass (`SecretRedactionProcessor`, `MachineTokenRedactionProcessor`, an application's own), each walking every record on its own. Nothing guarantees they all run, in which order, or that an application did not forget its own; N processors walk the same records N times.

## Task

1. A bundle (`WexampleSymfonySecurityBundle`) registered like its siblings.
2. **One** redaction processor service, registered on the logger (all channels), walking each record once — message, context, extra, nested arrays, string keys, objects, carried exceptions and their previous ones, as today.
3. **Maskers**: small services implementing an interface (`mask(string): string`, or a declarative "query parameter names" / "pattern" form), discovered by tag. `symfony-user` declares its link-signature masker, `symfony-api` its token masker, an application its own — without writing a processor.
4. Optionally, simple maskers declared in configuration (`wexample_symfony_security.redaction.query_parameters: [...]`, `patterns: [...]`) for an application that only needs to hide a parameter name.
5. One security-event log subscriber service if it simplifies the two current subclasses; keep the channels (`user_security`, `machine_security`) and event classes unchanged.
6. Migrate `symfony-user` and `symfony-api`: they require the bundle and ship maskers instead of processors. Their behaviour, channels and journal records must not change; their "search every record of every channel for each secret" tests stay green, untouched.
7. If the bundle is not registered, fail loudly at container build in `symfony-user` / `symfony-api` (a clear message), rather than silently logging unmasked secrets.

## Tests

- A masker from each source (package tag, application tag, configuration) masks in message, context, extra, objects and carried exceptions.
- The processor walks a record once whatever the number of maskers.
- Without the bundle registered, a `symfony-user` kernel fails to build with an explicit message.
- `symfony-user` and `symfony-api` suites green after migration.

## Work log

- `symfony-user` had moved on since `2b55774` (`2065ed4`, a new `access.denied` event type): compatible, nothing to adapt.
- Both apps run the suite packages' working trees through `vendor/wexample/*` symlinks, so they broke as soon as `symfony-user` asserted the bundle (`SecurityBundleHelper` not found). `dev:setup-composer` boots the kernel and could not run. The package was installed by hand with the same steps: a temporary path repository, `composer require wexample/symfony-security:@dev`, then `composer.json` and `composer.lock` restored and every local package force-symlinked again (its step 7). In app-board, `composer require` first reinstalled the lock's Packagist copies over 29 local symlinks; all were linked back.
- Mutation checks: the processor at priority `+1024` lets an application processor's `extra` through; no configuration maskers lets the configured parameter through; without the `hash` masker in `symfony-user`, `SecurityJournalTest` fails; without the `build()` check, `SecurityBundleRequiredTest` fails.
- Suites: `symfony-security` 15 tests / 73 assertions, `symfony-user` 104 / 1840, `symfony-api` 44 / 307.

## Reply

1. **Verdict**: implemented as asked, no demo. Commits: `symfony-security` `f41b107`, `symfony-user` `6a4279d`, `symfony-api` `c0bf7ca`; `config/bundles.php` in design-system `ab2ce48` and app-board `2598a16`.

2. **What the package does now**:
   - `WexampleSymfonySecurityBundle`, `extra.install.bundle_env: all` like its siblings.
   - **One** `Log\SecretRedactionProcessor`, tagged `monolog.processor` with `priority: -1024`, so it runs on every channel after the logger's other processors. It walks each record once (message, context, extra, nested arrays, string keys, objects, carried exceptions and their previous ones) and hands each string to every masker.
   - **Maskers**: services implementing `Interface\LogMaskerInterface` (`mask(string): string`), tagged by autoconfiguration (`wexample_symfony_security.log_masker`, tag priority orders them). Ready-made: `Log\Masker\QueryParameterLogMasker(names)` and `Log\Masker\PatternLogMasker(patterns)`.
   - **Configuration**, default empty: `wexample_symfony_security.redaction.query_parameters: []` and `.patterns: []` (each pattern validated at build).
   - `Helper\SecurityBundleHelper::assertRegistered($container, $requiredBy)`: `symfony-user` and `symfony-api` call it from `build()`. Without the bundle the kernel fails with `<Bundle> requires Wexample\SymfonySecurity\WexampleSymfonySecurityBundle, which masks its secrets in the logs: add it to config/bundles.php.`
   - `symfony-user` declares its masker in `services.yaml` only (`wexample_symfony_user.log_masker.link_signature`, `QueryParameterLogMasker(['hash'])`); `SecretRedactionProcessor` is gone. `symfony-api` ships `Log\MachineTokenLogMasker` (hint, foreign bearer, `access_token`) in place of `MachineTokenRedactionProcessor`.
   - Point 5: the security-event log subscribers stay one abstract class plus one small subclass per package. A single service would need a class→channel registry plus a logger per channel, which is more than the two 10-line subclasses whose `#[WithMonologChannel]` already creates the channel. Channels, event classes and records are unchanged.
   - `AbstractSecretRedactionProcessor` from `af1c50f` is removed: nothing outside `symfony-user` and `symfony-api` extended it.

3. **Found on the way**:
   - The redaction now runs after the other logger processors: an application processor adding the request URL to `extra` was walked or not depending on registration order. A test pins this.
   - Checked **over HTTP** in the design-system: a matched route logs `request_uri … hash=[redacted]`; a 404 whose `Referer` holds `hash=…&access_token=…` logs both `[redacted]` in the exception message (the user masker and the api masker through the one processor). No secret anywhere in `var/log/dev.log`.
   - App-board boots and `/login` answers 200. `/` answers 500 from a Postgres permission error (`global/pg_filenode.map`) already in its log on 2026-09-30, unrelated.
   - Left out: `symfony-security/composer.lock` and `symfony-api/composer.lock` (untracked), the apps' other pending changes, and the version bumps. **Before deploying either app**, `symfony-security` must be published and `symfony-user` / `symfony-api` republished with it. Their production `composer.lock` doesn't contain it yet, so the `bundles.php` line would fail there.

4. **Notice for the application agent**

> `wexample/symfony-security` is now a bundle, required by `symfony-user` and `symfony-api`: register it, or their kernel refuses to build.
>
> ```php
> // config/bundles.php
> Wexample\SymfonySecurity\WexampleSymfonySecurityBundle::class => ['all' => true],
> ```
>
> To hide an application secret in every log, no processor to write any more:
>
> ```yaml
> # config/packages/wexample_symfony_security.yaml
> wexample_symfony_security:
>   redaction:
>     query_parameters: [invite_token]
>     patterns: ['/(?<=X-Partner-Key: )\S+/']
> ```
>
> or, for a secret that needs code (a hint), a service implementing `Wexample\SymfonySecurity\Interface\LogMaskerInterface`, picked up by autoconfiguration. The masking covers message, context, extra, keys, objects and carried exceptions on every channel, after the application's own logger processors.
>
> Unchanged: the journals' channels (`user_security`, `machine_security`), event classes and records, and the shared `request_id`.
>
> Still open: a processor registered on a single handler (not on the logger) runs after the redaction, so what it adds is not masked.
