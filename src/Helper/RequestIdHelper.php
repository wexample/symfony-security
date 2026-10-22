<?php

namespace Wexample\SymfonySecurity\Helper;

use Symfony\Component\HttpFoundation\Request;

/**
 * The id tying together everything recorded during one request: the one a
 * proxy gave, or one of our own, the same for every package asking.
 */
class RequestIdHelper
{
    public const string HEADER = 'X-Request-Id';

    /**
     * Visible ASCII only, and short: the header comes from the client and
     * lands in every security record.
     */
    private const string ACCEPTED_PATTERN = '/^[\x21-\x7E]{1,128}$/';

    private const string ATTRIBUTE = '_wexample_security_request_id';

    public static function resolve(?Request $request): ?string
    {
        if (! $request) {
            return null;
        }

        if (! $request->attributes->has(self::ATTRIBUTE)) {
            $header = $request->headers->get(self::HEADER);

            $request->attributes->set(
                self::ATTRIBUTE,
                null !== $header && preg_match(self::ACCEPTED_PATTERN, $header) ? $header : bin2hex(random_bytes(8))
            );
        }

        return $request->attributes->get(self::ATTRIBUTE);
    }
}
