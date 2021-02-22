<?php

namespace SimpleAuth\Service;

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
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class ConfigurationService
{
    /** @var Configuration */
    private $config;

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
        $privateKey = null, $algorithm = null, $hash = null, $audience = null, $issuer = null, Clock $clock = null
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
    public function getConfiguration()
    {
        return $this->config;
    }

    /**
     * Get token
     *
     * @param Request $request request
     *
     * @return Token
     *
     * @throws UnauthorizedException
     */
    public function getToken(Request $request)
    {
        $header = $request->headers->getString('authorization');
        if (empty($header)) {
            throw new UnauthorizedException('No authorization token.');
        }
        $headerParts = explode(' ', $header);
        if (count($headerParts) !== 2 || $headerParts[0] !== 'Bearer' || empty($headerParts[1])) {
            throw new UnauthorizedException('Authorization token incorrect.');
        }

        return $this->config
            ->parser()
            ->parse($headerParts[1])
        ;
    }

    /**
     * Verify and validate
     *
     * @param Token  $token     token
     * @param string $publicKey public key
     *
     * @throws UnauthorizedException
     */
    public function verifyAndValidate(Token $token, $publicKey)
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
    public function isVerifiedAndValidated(Token $token, $publicKey)
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
    private function getSigner($algorithm = null, $hash = null)
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
