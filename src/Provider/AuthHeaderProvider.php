<?php

namespace SimpleAuth\Provider;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;

class AuthHeaderProvider
{
    /** @var Clock */
    private $clock;

    /** @var Configuration */
    private $config;

    /** @var string */
    private $issuer;

    /** @var int */
    private $expirationPeriod;

    /** @var string|null */
    private $audience;

    /**
     * Construct
     *
     * @param Configuration $config           config
     * @param string        $issuer           issuer
     * @param int           $expirationPeriod expiration period
     */
    public function __construct(Configuration $config, $issuer, $expirationPeriod = 60)
    {
        $this->clock = SystemClock::fromSystemTimezone();
        $this->config = $config;
        $this->issuer = $issuer;
        $this->expirationPeriod = $expirationPeriod;
    }

    /**
     * Set clock
     *
     * @param Clock $clock clock
     *
     * @return self
     */
    public function setClock(Clock $clock)
    {
        $this->clock = $clock;

        return $this;
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
        $now = $this->clock->now();
        $builder = $this->config->builder();
        $builder
            ->issuedBy($this->issuer)
            ->issuedAt($now)
            ->expiresAt($now->add(new DateInterval(sprintf('PT%dS', $this->expirationPeriod))))
        ;
        if (is_string($this->audience)) {
            $builder->permittedFor($this->audience);
        }

        return $builder
            ->getToken($this->config->signer(), $this->config->signingKey())
            ->toString()
        ;
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
