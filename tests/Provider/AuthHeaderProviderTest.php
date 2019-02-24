<?php

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Provider\AuthHeaderProvider;

final class AuthHeaderProviderTest extends TestCase
{
    /** @var string */
    private $issuer = 'issuer1';

    /** @var string */
    private $privateKey = '-----BEGIN RSA PRIVATE KEY-----
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
    private $publicKey = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuMdWncKKA5dEciISjChI
F9NMuxrS7E/D2bz2OGAEdXS+fIo4XG6EsC6qG/jO7PQafLRZCCpHVi0cqI2SIeP4
K2BMGwl3GN9XJf/VDr4GpLmUr/Vf/mEQpt4GaB2P+5VIhxDPjAN3jChem2F5QyhP
ZXgQI2eFtnue4NWdpGiOhBCbVebg46pM0KB6+biDjwk9iJE8XUH0va5xaXlMrMhi
A8P7UrCaQosQYFvWH+lXQ40fAwQs4nDr3lVXVonMGG3lYwQoPoHJwhNWKn3BYw5T
kjVpU867fQstZEqTL0OOXkxt+b/Bw0L4F6Uwy5W+9cDYSg8kCw7qDzzcRmEULEYl
rQIDAQAB
-----END PUBLIC KEY-----';

    /**
     * Test JWT generation
     */
    public function testJwtGeneration()
    {
        $provider = new AuthHeaderProvider(new Builder(), new Sha256(), $this->issuer, $this->privateKey);
        $jwt = $provider->getToken();
        $this->assertTrue(is_string($jwt));
        $this->assertEquals(3, count(explode('.', $jwt)));
    }

    /**
     * Test header generation
     */
    public function testHeaderGeneration()
    {
        $provider = new AuthHeaderProvider(new Builder(), new Sha256(), $this->issuer, $this->privateKey);
        $this->assertStringStartsWith('Authorization: Bearer ', $provider->getHeader());
    }

    /**
     * Test JWT checking
     */
    public function testJwtChecking()
    {
        $provider = new AuthHeaderProvider(new Builder(), new Sha256(), $this->issuer, $this->privateKey);
        $parser = new Parser();
        $token = $parser->parse($provider->getToken());
        $this->assertTrue($token->verify(new Sha256(), $this->publicKey));
        $this->assertTrue($token->validate(new ValidationData()));
    }
}
