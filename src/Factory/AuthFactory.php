<?php

namespace SimpleAuth\Factory;

use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Validation\Constraint;
use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Middleware\AuthListMiddleware;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Model\AuthItemInterface;
use SimpleAuth\Provider\AuthHeaderProvider;
use SimpleAuth\Service\ConfigurationService;

class AuthFactory
{
    /** @var string|null */
    private $algorithm;

    /** @var string|null */
    private $hash;

    /**
     * Construct
     *
     * @param string|null $algorithm   algorithm
     * @param string|null $hash        hash
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
        $config = new ConfigurationService($privateKey, $this->algorithm, $this->hash);

        return new AuthHeaderProvider($config->getConfiguration(), $issuer, $expirationPeriod);
    }

    /**
     * Get auth middleware
     *
     * @param string      $publicKey public key
     * @param string|null $audience  audience
     * @param string|null $issuer    issuer
     *
     * @return AuthMiddleware
     */
    public function getAuthMiddleware($publicKey, $audience = null, $issuer = null)
    {
        return new AuthMiddleware(
            new ConfigurationService(null, $this->algorithm, $this->hash, $audience, $issuer),
            $publicKey,
        );
    }

    /**
     * Get auth list middleware
     *
     * @param string[]    $publicKeys public keys
     * @param string|null $audience   audience
     * @param string|null $issuer     issuer
     *
     * @return AuthListMiddleware
     */
    public function getAuthListMiddleware(array $publicKeys, $audience = null, $issuer = null)
    {
        return new AuthListMiddleware(
            new ConfigurationService(null, $this->algorithm, $this->hash, $audience, $issuer),
            $publicKeys,
        );
    }

    /**
     * Get middleware
     *
     * @param AuthItemInterface[] $items    items
     * @param string|null         $audience audience
     *
     * @return AuthItemsMiddleware
     */
    public function getAuthItemsMiddleware(array $items, $audience = null)
    {
        return new AuthItemsMiddleware(
            new ConfigurationService(null, $this->algorithm, $this->hash, $audience),
            $items,
        );
    }
}
