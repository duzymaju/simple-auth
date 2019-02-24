<?php

namespace SimpleAuth\Provider;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;

class AuthHeaderProvider
{
    /** @var Builder */
    private $builder;

    /** @var Signer */
    private $signer;

    /** @var string */
    private $privateKey;

    /** @var int */
    private $expirationPeriod;

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
        $builder->setIssuer($issuer);

        $this->builder = $builder;
        $this->signer = $signer;
        $this->privateKey = $privateKey;
        $this->expirationPeriod = $expirationPeriod;
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
            ->unsign()
            ->setIssuedAt($now)
            ->setExpiration($now + $this->expirationPeriod)
            ->sign($this->signer, $this->privateKey)
        ;

        return (string) $this->builder->getToken();
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
