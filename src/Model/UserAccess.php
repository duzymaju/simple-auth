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
    /** @var string */
    const CLAIM_CAPABILITIES = 'capabilities';

    /** @var string */
    const CLAIM_EMAIL = 'email';

    /** @var string */
    const CLAIM_UUID = 'uuid';

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
    private DataSet $jwtClaims;

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
    public function getUuid(): ?string
    {
        if ($this->uuid === false) {
            $value = $this->getJwtClaim(self::CLAIM_UUID);
            $this->uuid = is_string($value) ? $value : null;
        }

        return $this->uuid;
    }

    /**
     * Get email
     *
     * @return string|null
     */
    public function getEmail(): ?string
    {
        if ($this->email === false) {
            $value = $this->getJwtClaim(self::CLAIM_EMAIL);
            $this->email = is_string($value) ? $value : null;
        }

        return $this->email;
    }

    /**
     * Get user ID
     *
     * @return string|null
     */
    public function getEmailHash(): ?string
    {
        $email = $this->getEmail();

        return isset($email) ? md5($email) : null;
    }

    /**
     * Get capabilities
     *
     * @return string[]
     */
    public function getCapabilities(): array
    {
        if ($this->capabilities === false) {
            $value = $this->getJwtClaim(self::CLAIM_CAPABILITIES);
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
    public function hasCapabilities(...$requiredCapabilities): bool
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
    public function checkCapabilitiesOrNoAccess(...$requiredCapabilities): self
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
    public function getIssuedAt(): ?DateTimeImmutable
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
    public function getExpiresAt(): ?DateTimeImmutable
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
    public function getIssuer(): ?string
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
    public function getAudience(): ?string
    {
        if ($this->audience === false) {
            $this->audience = $this->getJwtClaim(RegisteredClaims::AUDIENCE);
        }

        return $this->audience;
    }

    /**
     * Get JWT claims
     *
     * @return array
     */
    public function getJwtClaims(): array
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
    public function getJwtClaim(string $name, $defaultValue = null)
    {
        return $this->jwtClaims->has($name) ? $this->jwtClaims->get($name) : $defaultValue;
    }
}
