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

Everything is optional: nothing is masked by configuration by default, and the headers below are the defaults.

```yaml
# config/packages/wexample_symfony_security.yaml
wexample_symfony_security:
  redaction:
    # Query parameters whose value is masked: "/link?token=[redacted]".
    query_parameters: [token, signature]
    # Regular expressions whose matches are masked. What must stay readable
    # goes in a lookaround.
    patterns: ['/(?<=Bearer )\S+/', '/pk_[0-9a-f]{32}/']
  # Security headers on every main response. ~ leaves one out.
  headers:
    strict_transport_security: 'max-age=31536000; includeSubDomains'
    content_type_options: nosniff
    frame_options: SAMEORIGIN       # DENY when no page is ever framed
    referrer_policy: strict-origin-when-cross-origin
    content_security_policy: ~      # off by default
```

`symfony/monolog-bundle` registers the processor on every channel; without it, nothing is logged through Monolog and nothing needs masking.
