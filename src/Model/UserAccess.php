<?php

namespace SimpleAuth\Model;

use DateTime;
use DateTimeZone;
use Exception;
use SimpleStructure\Exception\UnauthorizedException;

class UserAccess
{
    /** @var string|null */
    private $email;

    /** @var string[] */
    private $capabilities = [];

    /** @var DateTime|null */
    private $issuedAt;

    /** @var DateTime|null */
    private $expiresAt;

    /** @var mixed[] */
    private $jwtClaims;

    /**
     * Construct
     *
     * @param mixed[] $jwtClaims JWT claims
     *
     * @throws Exception
     */
    public function __construct(array $jwtClaims)
    {
        $dateTimeZone = new DateTimeZone(date_default_timezone_get());

        $this->email = array_key_exists('email', $jwtClaims) && is_string($jwtClaims['email']) ?
            $jwtClaims['email'] : null;
        $this->capabilities = array_key_exists('capabilities', $jwtClaims) && is_array($jwtClaims['capabilities']) ?
            $jwtClaims['capabilities'] : [];
        $this->issuedAt = array_key_exists('iat', $jwtClaims) && is_int($jwtClaims['iat']) && $jwtClaims['iat'] > 0 ?
            new DateTime('@' . $jwtClaims['iat'], $dateTimeZone) : null;
        $this->expiresAt = array_key_exists('exp', $jwtClaims) && is_int($jwtClaims['exp']) && $jwtClaims['exp'] > 0 ?
            new DateTime('@' . $jwtClaims['exp'], $dateTimeZone) : null;
        $this->jwtClaims = $jwtClaims;
    }

    /**
     * Get email
     *
     * @return string|null
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * Get user ID
     *
     * @return string|null
     */
    public function getEmailHash()
    {
        return isset($this->email) ? md5($this->email) : null;
    }

    /**
     * Get capabilities
     *
     * @return string[]
     */
    public function getCapabilities()
    {
        return $this->capabilities;
    }

    /**
     * Has capabilities
     *
     * @param string ...$requiredCapabilities required capabilities
     *
     * @return bool
     */
    public function hasCapabilities(...$requiredCapabilities)
    {
        $difference = array_diff($requiredCapabilities, $this->getCapabilities());

        return count($difference) === 0;
    }

    /**
     * Check capabilities or no access
     *
     * @param string ...$requiredCapabilities required capabilities
     *
     * @return self
     *
     * @throws UnauthorizedException
     */
    public function checkCapabilitiesOrNoAccess(...$requiredCapabilities)
    {
        if (!$this->hasCapabilities(...$requiredCapabilities)) {
            throw new UnauthorizedException('User doesn\'t have required capabilities.');
        }

        return $this;
    }

    /**
     * Get issued at
     *
     * @return DateTime|null
     */
    public function getIssuedAt()
    {
        return $this->issuedAt;
    }

    /**
     * Get expires at
     *
     * @return DateTime|null
     */
    public function getExpiresAt()
    {
        return $this->expiresAt;
    }

    /**
     * Get JWT claims
     *
     * @return mixed[]
     */
    public function getJwtClaims()
    {
        return $this->jwtClaims;
    }

    /**
     * Get JWT claim
     *
     * @param string $name         name
     * @param mixed  $defaultValue default value
     *
     * @return mixed
     */
    public function getJwtClaim($name, $defaultValue = null)
    {
        return array_key_exists($name, $this->jwtClaims) ? $this->jwtClaims[$name] : $defaultValue;
    }
}
