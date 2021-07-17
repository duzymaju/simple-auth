<?php

namespace SimpleAuth\Provider;

use DateInterval;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;

class AuthTokenProvider
{
    /** @var Clock */
    private Clock $clock;

    /** @var Configuration */
    private Configuration $config;

    /** @var string */
    private string $issuer;

    /** @var int */
    private int $expirationPeriod;

    /** @var string|null */
    private ?string $audience = null;

    /**
     * Construct
     *
     * @param Configuration $config           config
     * @param string        $issuer           issuer
     * @param int           $expirationPeriod expiration period
     */
    public function __construct(Configuration $config, string $issuer, int $expirationPeriod = 60)
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
    public function setClock(Clock $clock): self
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
    public function setAudience(string $audience): self
    {
        $this->audience = $audience;

        return $this;
    }

    /**
     * Get token
     *
     * @param array $claims claims
     *
     * @return string
     */
    public function getToken(array $claims = []): string
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
        foreach ($claims as $name => $value) {
            $builder->withClaim($name, $value);
        }

        return $builder
            ->getToken($this->config->signer(), $this->config->signingKey())
            ->toString()
        ;
    }

    /**
     * Get header
     *
     * @param array $claims claims
     *
     * @return string
     */
    public function getHeader(array $claims = []): string
    {
        return 'Authorization: Bearer ' . $this->getToken($claims);
    }
}
