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
use SimpleAuth\Middleware\AuthListMiddleware;
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
        $builder = $this->getBuilder();
        $signer = $this->getSigner();

        return new AuthHeaderProvider($builder, $signer, $issuer, $privateKey, $expirationPeriod);
    }

    /**
     * Get auth middleware
     *
     * @param string      $publicKey public key
     * @param string|null $audience  audience
     *
     * @return AuthMiddleware
     */
    public function getAuthMiddleware($publicKey, $audience = null)
    {
        $parser = $this->getParser();
        $signer = $this->getSigner();
        $validationData = $this->getValidationData($audience);

        return new AuthMiddleware($parser, $signer, $validationData, $publicKey);
    }

    /**
     * Get auth list middleware
     *
     * @param string[]    $publicKeys public keys
     * @param string|null $audience   audience
     *
     * @return AuthListMiddleware
     */
    public function getAuthListMiddleware(array $publicKeys, $audience = null)
    {
        $parser = $this->getParser();
        $signer = $this->getSigner();
        $validationData = $this->getValidationData($audience);

        return new AuthListMiddleware($parser, $signer, $validationData, $publicKeys);
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
        $parser = $this->getParser();
        $signer = $this->getSigner();
        $validationData = $this->getValidationData($audience);

        return new AuthItemsMiddleware($parser, $signer, $validationData, $items);
    }

    /**
     * Get builder
     *
     * @return Builder
     */
    private function getBuilder()
    {
        return new Builder();
    }

    /**
     * Get parser
     *
     * @return Parser
     */
    private function getParser()
    {
        return new Parser();
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

    /**
     * Get validation data
     *
     * @param string|null $audience audience
     *
     * @return ValidationData
     */
    private function getValidationData($audience)
    {
        $validationData = new ValidationData();
        if (is_string($audience)) {
            $validationData->setAudience($audience);
        }

        return $validationData;
    }
}
