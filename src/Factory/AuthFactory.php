<?php

namespace SimpleAuth\Factory;

use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Middleware\AuthListMiddleware;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Model\AuthItemInterface;
use SimpleAuth\Provider\AuthTokenProvider;
use SimpleAuth\Service\ConfigurationService;

class AuthFactory
{
    /** @var string|null */
    private ?string $algorithm;

    /** @var string|null */
    private ?string $hash;

    /**
     * Construct
     *
     * @param string|null $algorithm   algorithm
     * @param string|null $hash        hash
     */
    public function __construct(?string $algorithm = null, ?string $hash = null)
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
     * @return AuthTokenProvider
     */
    public function getTokenProvider(
        string $issuer, string $privateKey, int $expirationPeriod = 60
    ): AuthTokenProvider {
        $config = new ConfigurationService($privateKey, $this->algorithm, $this->hash);

        return new AuthTokenProvider($config->getConfiguration(), $issuer, $expirationPeriod);
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
    public function getAuthMiddleware(
        string $publicKey, ?string $audience = null, ?string $issuer = null
    ): AuthMiddleware {
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
    public function getAuthListMiddleware(
        array $publicKeys, ?string $audience = null, ?string $issuer = null
    ): AuthListMiddleware {
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
    public function getAuthItemsMiddleware(array $items, ?string $audience = null): AuthItemsMiddleware
    {
        return new AuthItemsMiddleware(
            new ConfigurationService(null, $this->algorithm, $this->hash, $audience),
            $items,
        );
    }
}
