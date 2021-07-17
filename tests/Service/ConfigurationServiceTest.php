<?php

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;

final class ConfigurationServiceTest extends TestCase
{
    /** @var string */
    const PRIVATE_KEY = '-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAuMdWncKKA5dEciISjChIF9NMuxrS7E/D2bz2OGAEdXS+fIo4
XG6EsC6qG/jO7PQafLRZCCpHVi0cqI2SIeP4K2BMGwl3GN9XJf/VDr4GpLmUr/Vf
/mEQpt4GaB2P+5VIhxDPjAN3jChem2F5QyhPZXgQI2eFtnue4NWdpGiOhBCbVebg
46pM0KB6+biDjwk9iJE8XUH0va5xaXlMrMhiA8P7UrCaQosQYFvWH+lXQ40fAwQs
4nDr3lVXVonMGG3lYwQoPoHJwhNWKn3BYw5TkjVpU867fQstZEqTL0OOXkxt+b/B
w0L4F6Uwy5W+9cDYSg8kCw7qDzzcRmEULEYlrQIDAQABAoIBAGNpQ41uy4fxCy8I
a8giJ99BnCeR3+apZ2ouwp1D80IqBA3G41m/T/3lrTmNW+6ZyeJLuRaugGC5tpBs
UjGPj8XuciOdrQihqCZWhI8A51waSAd+0R1vpWDRVMsRFJS7FSEthywB9YBfe77G
61GZT1X9CVmy6Xpq+ehmpQB+DCa6SfGh+RDpI+A+usYKBsJ/cgJ3x0FhzqLxA/do
z77HgVJGggrk7esAt3lAj+U/OvphjUNz6bFGs4THSFerc/syKSZQmOob8+sg5FLm
J7rnv9bH2Vqe71nCONk/eFbRjQoMSROeJdw3hjssf/tDLU4oELs4pd256/4vJOg2
Emlvw3UCgYEA6RUolD1gVZyy7mnnEH9hwhC9R8mALxSrLv8sWGUNGjtIVROUEs8P
+cQnYncN8VQogQ7EzAwOLCTzu+ReY5lZVUUN9Up6B1D3WUSSjtnz8pjW149Q6cNK
7N/2Zf1OrHS30Qq5gIw+gOIRx4oA77zGiGXFGAsGfmf6YfbV1TGtlAMCgYEAyvJW
Uro9TCnAYYmTVjuhQ3msdb+jp7oMbETun7oKOyEsBUM0479vqCBiEZ1KQDC4PUtU
VMiWe1zNqG96NaVg9L6yoXB0mFgzIZoMuNr9y7ybqoA35niiV2Q6QmTVBFSTtjkQ
41N0Sh277mMyTwGGtdXNOuD7JJuoBBlYEa8QKI8CgYAxnP1cQIxG7Onxcb1rd5HZ
ezKvGycb3mxpvosz7Z6SXNgSs+4q6sRdx/ESNoFTQzSz8+7T+CT0JJF1BzFIRhYL
3n0QH2BGOmfMKpp/qckRdJMWozz35UgHj8yk/PxIHTgbWQsPX8rWKEjcjnWQkkA4
PGFtsrsZIQzc2Wu+y6pE/QKBgHapUT3XtSWGN/0Pwr0l6nmYd/T1E0xrpP3dJCTy
Uy8VizacgB01/qQwIwcnj5WOpvr3w5w7GHmS3pDAdZVOWC1iHvHz3ciBsYvRFeUz
7jck1WPQyl6QZGNyr/nIGSEKDr/6B9zTG+iGEC8ngu/c9ZX2J6RojY9vD8Mtyme0
k18TAoGAMqhsc44MUymaxkswt72pytFZHo8E5qhYEok0YOXH0+ZmCm0pvPw/EpIl
+Bhp3EbhWv/TREhiHmdkNImvXFxBx/XFwkevcG5taOovmJknOKSmwcRy93bWeTYS
sAufwwSmo4EG4ksKtaklUYMrcJR1VC1Bx2kEwckj9oUADnfaKu4=
-----END RSA PRIVATE KEY-----';

    /** @var string */
    const PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMdWncKKA5dEciISjChI
F9NMuxrS7E/D2bz2OGAEdXS+fIo4XG6EsC6qG/jO7PQafLRZCCpHVi0cqI2SIeP4
K2BMGwl3GN9XJf/VDr4GpLmUr/Vf/mEQpt4GaB2P+5VIhxDPjAN3jChem2F5QyhP
ZXgQI2eFtnue4NWdpGiOhBCbVebg46pM0KB6+biDjwk9iJE8XUH0va5xaXlMrMhi
A8P7UrCaQosQYFvWH+lXQ40fAwQs4nDr3lVXVonMGG3lYwQoPoHJwhNWKn3BYw5T
kjVpU867fQstZEqTL0OOXkxt+b/Bw0L4F6Uwy5W+9cDYSg8kCw7qDzzcRmEULEYl
rQIDAQAB
-----END PUBLIC KEY-----';

    /** @var string */
    const ISSUER = 'issuer1';

    /**
     * Test configuration getting
     *
     * @param string      $signerClass signer class
     * @param string|null $algorithm   algorithm
     * @param string|null $hash        hash
     * @param string|null $audience    audience
     * @param string|null $issuer      issuer
     *
     * @testWith ["Lcobucci\\JWT\\Signer\\Rsa\\Sha512", "rsa", "sha512", "audience1", "issuer1"]
     *           ["Lcobucci\\JWT\\Signer\\Rsa\\Sha384", "rsa", "sha384", null, "issuer2"]
     *           ["Lcobucci\\JWT\\Signer\\Rsa\\Sha256", "rsa", "sha256", "audience2", null]
     *           ["Lcobucci\\JWT\\Signer\\Rsa\\Sha256", "rsa", null, null, null]
     *           ["Lcobucci\\JWT\\Signer\\Rsa\\Sha256", null, null, null, null]
     *           ["Lcobucci\\JWT\\Signer\\Hmac\\Sha512", "hmac", "sha512", null, "issuer3"]
     *           ["Lcobucci\\JWT\\Signer\\Hmac\\Sha384", "hmac", "sha384", "audience3", "issuer4"]
     *           ["Lcobucci\\JWT\\Signer\\Hmac\\Sha256", "hmac", "sha256", null, null]
     *           ["Lcobucci\\JWT\\Signer\\Hmac\\Sha256", "hmac", null, null, null]
     */
    public function testConfigurationGetting(
        string $signerClass, ?string $algorithm, ?string $hash, ?string $audience, ?string $issuer
    ) {
        $service = new ConfigurationService(self::PRIVATE_KEY, $algorithm, $hash, $audience, $issuer);
        $config = $service->getConfiguration();

        $this->assertInstanceOf($signerClass, $config->signer());
        if (empty($audience)) {
            $this->assertDoesntHaveConstraint(Constraint\PermittedFor::class, $config);
        } else {
            $this->assertHasConstraint(Constraint\PermittedFor::class, $config);
        }
        if (empty($issuer)) {
            $this->assertDoesntHaveConstraint(Constraint\IssuedBy::class, $config);
        } else {
            $this->assertHasConstraint(Constraint\IssuedBy::class, $config);
        }
    }

    /**
     * Test incorrect token getting
     *
     * @param mixed  $tokenString token string
     * @param string $message     message
     *
     * @testWith ["", "No authorization token."]
     *           [null, "No authorization token."]
     *           ["abc", "Authorization token incorrect."]
     *           ["abc def", "Authorization token incorrect."]
     *           [" abc", "Authorization token incorrect."]
     *           ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbTEiOiJhIiwiY2xhaW0yIjoyfQ.Ajjfq2j7ItD_p0ZUQ1Dqv4nOjgbBb8vs93OexjPL9kIabc", "Authorization token incorrect."]
     */
    public function testIncorrectTokenGetting(?string $tokenString, string $message)
    {
        $service = new ConfigurationService();
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage($message);
        $service->getToken($tokenString);
    }

    /**
     * Test correct token getting
     */
    public function testCorrectTokenGetting()
    {
        $service = new ConfigurationService();
        $token = $service->getToken('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGFpbTEiOiJhIiwiY2xhaW0yIjoyfQ.' .
            'Ajjfq2j7ItD_p0ZUQ1Dqv4nOjgbBb8vs93OexjPL9kI');
        $claims = $token->claims();
        $this->assertEquals(['claim1' => 'a', 'claim2' => 2], $claims->all());
    }

    /**
     * Test validating invalid tokens
     *
     * @param string|null $audience audience
     * @param string|null $issuer   issuer
     * @param array       $claims   claims
     *
     * @throws Exception
     *
     * @testWith ["audience1", null, {"iss": "issuer1"}]
     *           [null, "issuer1", {"aud": ["audience1"]}]
     *           ["audience1", "issuer1", {}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iss": "issuer1", "exp": 1612582559}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iat": 1612582561, "iss": "issuer1", "exp": 1612586161}]
     */
    public function testValidatingInvalidTokens(?string $audience, ?string $issuer, array $claims)
    {
        $clock = new Lcobucci\Clock\FrozenClock(new DateTimeImmutable('2021-02-06T03:36:00'));
        $service = new ConfigurationService(null, 'rsa', 'sha256', $audience, $issuer, $clock);
        $token = $this->getToken($service->getConfiguration(), ['alg' => 'RS256', 'typ' => 'JWT'], $claims);
        $this->expectException(UnauthorizedException::class);
        $service->verifyAndValidate($token, self::PUBLIC_KEY);
    }

    /**
     * Test validating valid token
     *
     * @param string|null $audience audience
     * @param string|null $issuer   issuer
     * @param array       $claims   claims
     *
     * @throws Exception
     *
     * @testWith [null, null, {"exp": 1612582561}]
     *           ["audience1", null, {"aud": ["audience1"]}]
     *           [null, "issuer1", {"iss": "issuer1"}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iss": "issuer1"}]
     */
    public function testValidatingValidToken(?string $audience, ?string $issuer, array $claims)
    {
        $clock = new Lcobucci\Clock\FrozenClock(new DateTimeImmutable('2021-02-06T03:36:00'));
        $service = new ConfigurationService(null, 'rsa', 'sha256', $audience, $issuer, $clock);
        $token = $this->getToken($service->getConfiguration(), ['alg' => 'RS256', 'typ' => 'JWT'], $claims);
        try {
            $service->verifyAndValidate($token, self::PUBLIC_KEY);
            $this->assertTrue(true, 'UnauthorizedException has to be thrown.');
        } catch (UnauthorizedException $exception) {
            $this->assertTrue(
                false,
                sprintf('UnauthorizedException has been thrown incorrectly. %s', $exception->getMessage()),
            );
        }
    }

    /**
     * Test checking invalid tokens
     *
     * @param string|null $audience audience
     * @param string|null $issuer   issuer
     * @param array       $claims   claims
     *
     * @throws Exception
     *
     * @testWith ["audience1", null, {"iss": "issuer1"}]
     *           [null, "issuer1", {"aud": ["audience1"]}]
     *           ["audience1", "issuer1", {}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iss": "issuer1", "exp": 1612582559}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iat": 1612582561, "iss": "issuer1", "exp": 1612586161}]
     */
    public function testCheckingInvalidTokens(?string $audience, ?string $issuer, array $claims)
    {
        $clock = new Lcobucci\Clock\FrozenClock(new DateTimeImmutable('2021-02-06T03:36:00'));
        $service = new ConfigurationService(null, 'rsa', 'sha256', $audience, $issuer, $clock);
        $token = $this->getToken($service->getConfiguration(), ['alg' => 'RS256', 'typ' => 'JWT'], $claims);
        $this->assertFalse($service->isVerifiedAndValidated($token, self::PUBLIC_KEY));
    }

    /**
     * Test checking valid token
     *
     * @param string|null $audience audience
     * @param string|null $issuer   issuer
     * @param array       $claims   claims
     *
     * @throws Exception
     *
     * @testWith [null, null, {"exp": 1612582561}]
     *           ["audience1", null, {"aud": ["audience1"]}]
     *           [null, "issuer1", {"iss": "issuer1"}]
     *           ["audience1", "issuer1", {"aud": ["audience1"], "iss": "issuer1"}]
     */
    public function testCheckingValidToken(?string $audience, ?string $issuer, array $claims)
    {
        $clock = new Lcobucci\Clock\FrozenClock(new DateTimeImmutable('2021-02-06T03:36:00'));
        $service = new ConfigurationService(null, 'rsa', 'sha256', $audience, $issuer, $clock);
        $token = $this->getToken($service->getConfiguration(), ['alg' => 'RS256', 'typ' => 'JWT'], $claims);
        $this->assertTrue($service->isVerifiedAndValidated($token, self::PUBLIC_KEY));
    }

    /**
     * Get token
     *
     * @param Configuration $config  config
     * @param array         $headers headers
     * @param array         $claims  claims
     *
     * @return Token\Plain
     *
     * @throws Exception
     */
    private function getToken(Configuration $config, array $headers, array $claims): Token\Plain
    {
        $builder = $config->builder();
        foreach ($headers as $name => $value) {
            $builder->withHeader($name, $value);
        }
        foreach ($claims as $name => $value) {
            switch ($name) {
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor(...$value);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(new DateTimeImmutable(sprintf('@%d', $value)));
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(new DateTimeImmutable(sprintf('@%d', $value)));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($value);
                    break;
                default:
                    $builder->withClaim($name, $value);
            }
        }

        return $builder->getToken($config->signer(), Key\InMemory::plainText(self::PRIVATE_KEY));
    }

    /**
     * Assert doesn't have constraint
     *
     * @param string        $className class name
     * @param Configuration $config    config
     */
    private function assertDoesntHaveConstraint(string $className, Configuration $config)
    {
        $constraint = $this->findConstraint($className, $config);
        if (isset($constraint)) {
            $this->assertTrue(false, sprintf('Constraint %s exists while it shouldn\'t.', $className));
        }
    }

    /**
     * Assert has constraint
     *
     * @param string        $className class name
     * @param Configuration $config    config
     */
    private function assertHasConstraint(string $className, Configuration $config)
    {
        $constraint = $this->findConstraint($className, $config);
        if (!isset($constraint)) {
            $this->assertTrue(false, sprintf('Constraint %s doesn\'t exist while it should.', $className));
        }
    }

    /**
     * Find constraint
     *
     * @param string        $className class name
     * @param Configuration $config    config
     *
     * @return Constraint|null
     */
    private function findConstraint(string $className, Configuration $config): ?Constraint
    {
        foreach ($config->validationConstraints() as $constraint) {
            if ($constraint instanceof $className) {
                return $constraint;
            }
        }

        return null;
    }
}
