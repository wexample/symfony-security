<?php

namespace Wexample\SymfonySecurity\Tests\Fixtures\App\Log;

use Monolog\Attribute\AsMonologProcessor;
use Monolog\LogRecord;

/**
 * As an application adds the request URL to every record, at the default
 * priority.
 */
#[AsMonologProcessor]
class RequestUrlProcessor
{
    public const string URL = '/reset?sig=s1gnatureFromExtra';

    public function __invoke(LogRecord $record): LogRecord
    {
        return $record->with(extra: $record->extra + ['url' => self::URL]);
    }
}
