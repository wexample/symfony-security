## Installation

```bash
composer require wexample/symfony-security
```

```php
// config/bundles.php
Wexample\SymfonySecurity\WexampleSymfonySecurityBundle::class => ['all' => true],
```

`symfony-user` and `symfony-api` check it at container build: without it, their kernel fails with `… requires Wexample\SymfonySecurity\WexampleSymfonySecurityBundle, which masks its secrets in the logs`, rather than logging their secrets unmasked. A bundle of the suite relying on it does the same from its `build()`:

```php
SecurityBundleHelper::assertRegistered($container, static::class);
```

## Configuration

Everything is optional; nothing is masked by configuration by default.

```yaml
# config/packages/wexample_symfony_security.yaml
wexample_symfony_security:
  redaction:
    # Query parameters whose value is masked: "/link?token=[redacted]".
    query_parameters: [token, signature]
    # Regular expressions whose matches are masked. What must stay readable
    # goes in a lookaround.
    patterns: ['/(?<=Bearer )\S+/', '/pk_[0-9a-f]{32}/']
```

`symfony/monolog-bundle` registers the processor on every channel; without it, nothing is logged through Monolog and nothing needs masking.
