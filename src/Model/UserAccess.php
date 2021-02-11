<?php

namespace SimpleAuth\Model;

use DateTime;
use DateTimeZone;
use Exception;
use Lcobucci\JWT\Claim;
use SimpleStructure\Exception\UnauthorizedException;

class UserAccess
{
    /** @var string|false|null */
    private $uuid = false;

    /** @var string|false|null */
    private $email = false;

    /** @var string[]|false */
    private $capabilities = false;

    /** @var DateTime|false|null */
    private $issuedAt = false;

    /** @var DateTime|false|null */
    private $expiresAt = false;

    /** @var string|false|null */
    private $audience = false;

    /** @var mixed[] */
    private $jwtClaims = [];

    /**
     * Construct
     *
     * @param Claim[] $jwtClaims JWT claims
     */
    public function __construct(array $jwtClaims)
    {
        /** @var Claim $claim */
        foreach ($jwtClaims as $claim) {
            $this->jwtClaims[$claim->getName()] = $claim->getValue();
        }
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
     * @return DateTime|null
     *
     * @throws Exception
     */
    public function getIssuedAt()
    {
        if ($this->issuedAt === false) {
            $value = $this->getJwtClaim('iat');
            $dateTimeZone = new DateTimeZone(date_default_timezone_get());
            $this->issuedAt = is_int($value) && $value > 0 ? new DateTime('@' . $value, $dateTimeZone) : null;
        }

        return $this->issuedAt;
    }

    /**
     * Get expires at
     *
     * @return DateTime|null
     *
     * @throws Exception
     */
    public function getExpiresAt()
    {
        if ($this->expiresAt === false) {
            $value = $this->getJwtClaim('exp');
            $dateTimeZone = new DateTimeZone(date_default_timezone_get());
            $this->expiresAt = is_int($value) && $value > 0 ? new DateTime('@' . $value, $dateTimeZone) : null;
        }

        return $this->expiresAt;
    }

    /**
     * Get audience
     *
     * @return string|null
     *
     * @throws Exception
     */
    public function getAudience()
    {
        if ($this->audience === false) {
            $this->audience = $this->getJwtClaim('aud');
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
