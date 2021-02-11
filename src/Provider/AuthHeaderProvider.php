<?php

namespace SimpleAuth\Provider;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key;

class AuthHeaderProvider
{
    /** @var Builder */
    private $builder;

    /** @var Signer */
    private $signer;

    /** @var Key */
    private $privateKey;

    /** @var int */
    private $expirationPeriod;

    /** @var string|null */
    private $audience;

    /**
     * Construct
     *
     * @param Builder $builder          builder
     * @param Signer  $signer           signer
     * @param string  $issuer           issuer
     * @param string  $privateKey       private key
     * @param int     $expirationPeriod expiration period
     */
    public function __construct(Builder $builder, Signer $signer, $issuer, $privateKey, $expirationPeriod = 60)
    {
        $builder->issuedBy($issuer);

        $this->builder = $builder;
        $this->signer = $signer;
        $this->privateKey = new Key($privateKey);
        $this->expirationPeriod = $expirationPeriod;
    }

    /**
     * Set audience
     *
     * @param string $audience audience
     *
     * @return self
     */
    public function setAudience($audience)
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * Get token
     *
     * @return string
     */
    public function getToken()
    {
        $now = time();
        $this->builder
            ->issuedAt($now)
            ->expiresAt($now + $this->expirationPeriod)
        ;
        if (is_string($this->audience)) {
            $this->builder->permittedFor($this->audience);
        }

        return (string) $this->builder->getToken($this->signer, $this->privateKey);
    }

    /**
     * Get header
     *
     * @return string
     */
    public function getHeader()
    {
        return 'Authorization: Bearer ' . $this->getToken();
    }
}
