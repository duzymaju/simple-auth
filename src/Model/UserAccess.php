<?php

namespace SimpleAuth\Model;

use DateTime;
use DateTimeZone;
use Exception;

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

        $this->email = is_string($jwtClaims['email']) ? $jwtClaims['email'] : null;
        $this->capabilities = is_array($jwtClaims['capabilities']) ? $jwtClaims['capabilities'] : [];
        $this->issuedAt = is_int($jwtClaims['iat']) && $jwtClaims['iat'] > 0 ?
            new DateTime('@' . $jwtClaims['iat'], $dateTimeZone) : null;
        $this->expiresAt = is_int($jwtClaims['exp']) && $jwtClaims['exp'] > 0 ?
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
