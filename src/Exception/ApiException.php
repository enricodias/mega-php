<?php

declare(strict_types=1);

namespace Mega\Exception;

/**
 * Thrown when the MEGA API returns an error code.
 */
class ApiException extends MegaException
{
    /**
     * MEGA API error code constants.
     */
    const EINTERNAL    = -1;
    const EARGS        = -2;
    const EAGAIN       = -3;
    const ERATELIMIT   = -4;
    const EFAILED      = -5;
    const ETOOMANY     = -6;
    const ERANGE       = -7;
    const EEXPIRED     = -8;
    const ENOENT       = -9;
    const ECIRCULAR    = -10;
    const EACCESS      = -11;
    const EEXIST       = -12;
    const EINCOMPLETE  = -13;
    const EKEY         = -14;
    const ESID         = -15;
    const EBLOCKED     = -16;
    const EOVERQUOTA   = -17;
    const ETEMPUNAVAIL = -18;

    /**
     * @var array<int, string>
     */
    private static $messages = [
        self::EINTERNAL    => 'An internal error has occurred. Please submit a bug report, detailing the exact circumstances in which this error occurred.',
        self::EARGS        => 'You have passed invalid arguments to this command.',
        self::EAGAIN       => 'A temporary congestion or server malfunction prevented your request from being processed. No data was altered. Retry with exponential backoff.',
        self::ERATELIMIT   => 'You have exceeded your command weight per time quota. Please wait a few seconds, then try again.',
        self::EFAILED      => 'The upload failed. Please restart it from scratch.',
        self::ETOOMANY     => 'Too many concurrent IP addresses are accessing this upload target URL.',
        self::ERANGE       => 'The upload file packet is out of range or not starting and ending on a chunk boundary.',
        self::EEXPIRED     => 'The upload target URL you are trying to access has expired. Please request a fresh one.',
        self::ENOENT       => 'Object (typically, node or user) not found.',
        self::ECIRCULAR    => 'Circular linkage attempted.',
        self::EACCESS      => 'Access violation (e.g., trying to write to a read-only share).',
        self::EEXIST       => 'Trying to create an object that already exists.',
        self::EINCOMPLETE  => 'Trying to access an incomplete resource.',
        self::EKEY         => 'A decryption operation failed.',
        self::ESID         => 'Invalid or expired user session, please re-login.',
        self::EBLOCKED     => 'User blocked.',
        self::EOVERQUOTA   => 'Request over quota.',
        self::ETEMPUNAVAIL => 'Resource temporarily not available, please try again later.',
    ];

    public static function fromCode(int $code): self
    {
        $message = self::$messages[$code] ?? \sprintf('Unknown MEGA API error code: %d', $code);

        return new self($message, $code);
    }
}
