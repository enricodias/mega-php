<?php

declare(strict_types=1);

namespace Mega\Service;

use Mega\Crypto\A32;
use Mega\Crypto\Aes;
use Mega\Crypto\Base64Url;
use Mega\Crypto\Rsa;
use Mega\Entity\Session;
use Mega\Exception\AuthException;

/**
 * Builds a Session from a raw MEGA login ('us') command response.
 */
class SessionAuthenticator
{
    /**
     * @param array<string, mixed> $response
     *
     * @throws AuthException
     */
    public function buildSessionFromLoginResponse(array $response, string $passwordKey): Session
    {
        if (!\array_key_exists('k', $response)) {
            throw new AuthException('Login response missing master key.');
        }

        $masterKey = A32::fromBase64($response['k']);
        if (\count($masterKey) !== 4) {
            throw new AuthException('Unexpected master key length in login response.');
        }

        $masterKey = Aes::decryptKey($passwordKey, $masterKey);

        if (!\array_key_exists('csid', $response)) {
            throw new AuthException('Login response missing session challenge (csid). Two-factor or alternate login flows are not supported.');
        }

        if (!\array_key_exists('privk', $response)) {
            throw new AuthException('Login response missing private key (privk).');
        }

        $masterKeyStr = A32::toString($masterKey);
        $privkA32 = Aes::decryptKey($masterKeyStr, A32::fromBase64($response['privk']));
        $rsaPrivateKey = Rsa::decomposeMpiPrivateKey(A32::toString($privkA32));

        $csidBytes = Base64Url::decode($response['csid']);
        $csidInt = A32::mpiToInt($csidBytes);
        $sidRaw = Rsa::decrypt($csidInt, $rsaPrivateKey[0], $rsaPrivateKey[1], $rsaPrivateKey[2]);
        $sessionId = Base64Url::encode(\substr(\strrev($sidRaw), 0, 43));

        return new Session($masterKey, $sessionId, $rsaPrivateKey);
    }
}
