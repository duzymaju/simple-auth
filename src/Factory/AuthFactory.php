<?php

namespace SimpleAuth\Factory;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Model\AuthItemInterface;
use SimpleAuth\Provider\AuthHeaderProvider;

class AuthFactory
{
    /** @var string|null */
    private $algorithm;

    /** @var string|null */
    private $hash;

    /**
     * Construct
     *
     * @param string|null $algorithm algorithm
     * @param string|null $hash      hash
     */
    public function __construct($algorithm = null, $hash = null)
    {
        $this->algorithm = $algorithm;
        $this->hash = $hash;
    }

    /**
     * Get header provider
     *
     * @param string  $issuer           issuer
     * @param string  $privateKey       private key
     * @param int     $expirationPeriod expiration period
     *
     * @return AuthHeaderProvider
     */
    public function getHeaderProvider($issuer, $privateKey, $expirationPeriod = 60)
    {
        return new AuthHeaderProvider(new Builder(), $this->getSigner(), $issuer, $privateKey, $expirationPeriod);
    }

    /**
     * Get auth middleware
     *
     * @param string $publicKey public key
     *
     * @return AuthMiddleware
     */
    public function getAuthMiddleware($publicKey)
    {
        return new AuthMiddleware(new Parser(), $this->getSigner(), new ValidationData(), $publicKey);
    }

    /**
     * Get middleware
     *
     * @param AuthItemInterface[] $items items
     *
     * @return AuthItemsMiddleware
     */
    public function getAuthItemsMiddleware(array $items)
    {
        return new AuthItemsMiddleware(new Parser(), $this->getSigner(), new ValidationData(), $items);
    }

    /**
     * Get signer
     *
     * @return Signer
     */
    private function getSigner()
    {
        switch ($this->algorithm) {
            case 'ecdsa':
                switch ($this->hash) {
                    case 'sha512':
                        return new Ecdsa\Sha512();

                    case 'sha384':
                        return new Ecdsa\Sha384();

                    case 'sha256':
                    default;
                        return new Ecdsa\Sha256();
                }

            case 'hmac':
                switch ($this->hash) {
                    case 'sha512':
                        return new Hmac\Sha512();

                    case 'sha384':
                        return new Hmac\Sha384();

                    case 'sha256':
                    default;
                        return new Hmac\Sha256();
                }

            case 'rsa':
            default:
                switch ($this->hash) {
                    case 'sha512':
                        return new Rsa\Sha512();

                    case 'sha384':
                        return new Rsa\Sha384();

                    case 'sha256':
                    default;
                        return new Rsa\Sha256();
                }
        }
    }
}
