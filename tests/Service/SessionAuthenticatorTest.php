<?php

declare(strict_types=1);

namespace Mega\Tests\Service;

use Mega\Crypto\A32;
use Mega\Exception\AuthException;
use Mega\Service\SessionAuthenticator;
use PHPUnit\Framework\TestCase;

class SessionAuthenticatorTest extends TestCase
{
    public function testThrowsWhenMasterKeyMissing(): void
    {
        $authenticator = new SessionAuthenticator();

        $this->expectException(AuthException::class);

        $authenticator->buildSessionFromLoginResponse([], 'password-key');
    }

    public function testThrowsWhenMasterKeyLengthIsNotFourWords(): void
    {
        $authenticator = new SessionAuthenticator();

        $response = [
            'k' => A32::toBase64([1, 2, 3]),
        ];

        $this->expectException(AuthException::class);

        $authenticator->buildSessionFromLoginResponse($response, 'password-key');
    }

    public function testThrowsWhenCsidMissing(): void
    {
        $authenticator = new SessionAuthenticator();

        $response = [
            'k' => A32::toBase64([1, 2, 3, 4]),
        ];

        $this->expectException(AuthException::class);

        $authenticator->buildSessionFromLoginResponse($response, \str_repeat("\x00", 16));
    }

    public function testThrowsWhenPrivkMissing(): void
    {
        $authenticator = new SessionAuthenticator();

        $response = [
            'k'    => A32::toBase64([1, 2, 3, 4]),
            'csid' => 'anything',
        ];

        $this->expectException(AuthException::class);

        $authenticator->buildSessionFromLoginResponse($response, \str_repeat("\x00", 16));
    }
}
