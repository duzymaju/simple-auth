<?php

namespace SimpleAuth\Model;

use DateTime;
use DateTimeZone;
use Exception;

class Jwt
{
    /** @var string|null */
    private $email;

    /** @var string[] */
    private $capabilities = [];

    /** @var DateTime|null */
    private $issuedAt;

    /** @var DateTime|null */
    private $expiration;

    /**
     * Construct
     *
     * @param string|null   $email        email
     * @param string[]|null $capabilities capabilities
     * @param int|null      $issuedAt     issued at
     * @param int|null      $expiration   expiration
     *
     * @throws Exception
     */
    public function __construct($email, $capabilities, $issuedAt, $expiration)
    {
        $dateTimeZone = new DateTimeZone(date_default_timezone_get());

        $this->email = is_string($email) ? $email : null;
        $this->capabilities = is_array($capabilities) ? $capabilities : [];
        $this->issuedAt = is_int($issuedAt) && $issuedAt > 0 ? new DateTime('@' . $issuedAt, $dateTimeZone) : null;
        $this->expiration = is_int($expiration) && $expiration > 0 ? new DateTime('@' . $expiration, $dateTimeZone) :
            null;
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
     * Get expiration
     *
     * @return DateTime|null
     */
    public function getExpiration()
    {
        return $this->expiration;
    }
}
