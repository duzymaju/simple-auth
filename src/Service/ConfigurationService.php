<?php

namespace SimpleAuth\Service;

use InvalidArgumentException;
use Lcobucci\Clock\Clock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use RuntimeException;
use SimpleStructure\Exception\UnauthorizedException;

class ConfigurationService
{
    /** @var Configuration */
    private Configuration $config;

    /**
     * Construct
     *
     * @param string|null $privateKey private key
     * @param string|null $algorithm  algorithm
     * @param string|null $hash       hash
     * @param string|null $audience   audience
     * @param string|null $issuer     issuer
     * @param Clock|null  $clock      clock
     */
    public function __construct(
        ?string $privateKey = null, ?string $algorithm = null, ?string $hash = null, ?string $audience = null,
        ?string $issuer = null, ?Clock $clock = null
    ) {
        $this->config = Configuration::forAsymmetricSigner(
            $this->getSigner($algorithm, $hash),
            !empty($privateKey) ? Key\InMemory::plainText($privateKey) : Key\InMemory::empty(),
            Key\InMemory::empty(),
        );
        $constraints = [
            new Constraint\LooseValidAt(isset($clock) ? $clock : SystemClock::fromSystemTimezone()),
        ];
        if (!empty($audience)) {
            $constraints[] = new Constraint\PermittedFor($audience);
        }
        if (!empty($issuer)) {
            $constraints[] = new Constraint\IssuedBy($issuer);
        }
        $this->config->setValidationConstraints(...$constraints);
    }

    /**
     * Get configuration
     *
     * @return Configuration
     */
    public function getConfiguration(): Configuration
    {
        return $this->config;
    }

    /**
     * Get token
     *
     * @param string|null $tokenString token string
     *
     * @return Token
     *
     * @throws UnauthorizedException
     */
    public function getToken(?string $tokenString): Token
    {
        if (empty($tokenString)) {
            throw new UnauthorizedException('No authorization token.');
        }
        try {
            return $this->config
                ->parser()
                ->parse($tokenString)
                ;
        } catch (RuntimeException | InvalidArgumentException $exception) {
            throw new UnauthorizedException('Authorization token incorrect.');
        }
    }

    /**
     * Verify and validate
     *
     * @param Token  $token     token
     * @param string $publicKey public key
     *
     * @throws UnauthorizedException
     */
    public function verifyAndValidate(Token $token, string $publicKey)
    {
        $validator = $this->config->validator();
        try {
            $validator->assert(
                $token,
                new Constraint\SignedWith($this->config->signer(), Key\InMemory::plainText($publicKey)),
                ...$this->config->validationConstraints(),
            );
        } catch (RequiredConstraintsViolated $exception) {
            throw new UnauthorizedException('Authorization token invalid.', $exception);
        }
    }

    /**
     * Is verified and validated
     *
     * @param Token  $token     token
     * @param string $publicKey public key
     *
     * @return bool
     */
    public function isVerifiedAndValidated(Token $token, string $publicKey): bool
    {
        try {
            $this->verifyAndValidate($token, $publicKey);
        } catch (UnauthorizedException $exception) {
            return false;
        }

        return true;
    }

    /**
     * Get signer
     *
     * @param string|null $algorithm algorithm
     * @param string|null $hash      hash
     *
     * @return Signer
     */
    private function getSigner(?string $algorithm = null, ?string $hash = null): Signer
    {
        switch ($algorithm) {
            case 'hmac':
                switch ($hash) {
                    case 'sha512':
                        return new Hmac\Sha512();

                    case 'sha384':
                        return new Hmac\Sha384();

                    case 'sha256':
                    default;
                        return new Hmac\Sha256();
                }

            case 'rsa':
            default:
                switch ($hash) {
                    case 'sha512':
                        return new Rsa\Sha512();

                    case 'sha384':
                        return new Rsa\Sha384();

                    case 'sha256':
                    default;
                        return new Rsa\Sha256();
                }
        }
    }
}
