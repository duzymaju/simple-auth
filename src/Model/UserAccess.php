<?php

namespace SimpleAuth\Model;

use DateTimeImmutable;
use DateTimeZone;
use Exception;
use Lcobucci\JWT\Token\DataSet;
use Lcobucci\JWT\Token\RegisteredClaims;
use SimpleStructure\Exception\UnauthorizedException;

class UserAccess
{
    /** @var string|false|null */
    private $uuid = false;

    /** @var string|false|null */
    private $email = false;

    /** @var string[]|false */
    private $capabilities = false;

    /** @var DateTimeImmutable|false|null */
    private $issuedAt = false;

    /** @var DateTimeImmutable|false|null */
    private $expiresAt = false;

    /** @var string|false|null */
    private $issuer = false;

    /** @var string|false|null */
    private $audience = false;

    /** @var DataSet */
    private $jwtClaims;

    /**
     * Construct
     *
     * @param DataSet $jwtClaims JWT claims
     */
    public function __construct(DataSet $jwtClaims)
    {
        $this->jwtClaims = $jwtClaims;
    }

    /**
     * Get UUID
     *
     * @return string|null
     */
    public function getUuid()
    {
        if ($this->uuid === false) {
            $value = $this->getJwtClaim('uuid');
            $this->uuid = is_string($value) ? $value : null;
        }

        return $this->uuid;
    }

    /**
     * Get email
     *
     * @return string|null
     */
    public function getEmail()
    {
        if ($this->email === false) {
            $value = $this->getJwtClaim('email');
            $this->email = is_string($value) ? $value : null;
        }

        return $this->email;
    }

    /**
     * Get user ID
     *
     * @return string|null
     */
    public function getEmailHash()
    {
        $email = $this->getEmail();

        return isset($email) ? md5($email) : null;
    }

    /**
     * Get capabilities
     *
     * @return string[]
     */
    public function getCapabilities()
    {
        if ($this->capabilities === false) {
            $value = $this->getJwtClaim('capabilities');
            $this->capabilities = is_array($value) ? $value : [];
        }

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
     * @return DateTimeImmutable|null
     *
     * @throws Exception
     */
    public function getIssuedAt()
    {
        if ($this->issuedAt === false) {
            $value = $this->getJwtClaim(RegisteredClaims::ISSUED_AT);
            $dateTimeZone = new DateTimeZone(date_default_timezone_get());
            $this->issuedAt = is_int($value) && $value > 0 ? new DateTimeImmutable('@' . $value, $dateTimeZone) : null;
        }

        return $this->issuedAt;
    }

    /**
     * Get expires at
     *
     * @return DateTimeImmutable|null
     *
     * @throws Exception
     */
    public function getExpiresAt()
    {
        if ($this->expiresAt === false) {
            $value = $this->getJwtClaim(RegisteredClaims::EXPIRATION_TIME);
            $dateTimeZone = new DateTimeZone(date_default_timezone_get());
            $this->expiresAt = is_int($value) && $value > 0 ? new DateTimeImmutable('@' . $value, $dateTimeZone) : null;
        }

        return $this->expiresAt;
    }

    /**
     * Get issuer
     *
     * @return string|null
     */
    public function getIssuer()
    {
        if ($this->issuer === false) {
            $this->issuer = $this->getJwtClaim(RegisteredClaims::ISSUER);
        }

        return $this->issuer;
    }

    /**
     * Get audience
     *
     * @return string|null
     */
    public function getAudience()
    {
        if ($this->audience === false) {
            $this->audience = $this->getJwtClaim(RegisteredClaims::AUDIENCE);
        }

        return $this->audience;
    }

    /**
     * Get JWT claims
     *
     * @return mixed[]
     */
    public function getJwtClaims()
    {
        return $this->jwtClaims->all();
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
        return $this->jwtClaims->has($name) ? $this->jwtClaims->get($name) : $defaultValue;
    }
}
