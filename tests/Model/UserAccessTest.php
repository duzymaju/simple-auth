<?php

use Lcobucci\JWT\Token\DataSet;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Model\UserAccess;
use SimpleStructure\Exception\UnauthorizedException;

final class UserAccessTest extends TestCase
{
    /**
     * Test UUID
     *
     * @param array       $claims claims
     * @param string|null $result result
     *
     * @testWith [{"uuid": "abc"}, "abc"]
     *           [{"uuid": 123}, null]
     *           [{}, null]
     */
    public function testUuid(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getUuid());
    }

    /**
     * Test e-mail
     *
     * @param array       $claims claims
     * @param string|null $result result
     *
     * @testWith [{"email": "abc@example.com"}, "abc@example.com"]
     *           [{"email": 123}, null]
     *           [{}, null]
     */
    public function testEmail(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getEmail());
    }

    /**
     * Test e-mail hash
     *
     * @param array       $claims claims
     * @param string|null $result result
     *
     * @testWith [{"email": "abc@example.com"}, "b28d5fe8da784e36235a487c03a47353"]
     *           [{"email": 123}, null]
     *           [{}, null]
     */
    public function testEmailHash(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getEmailHash());
    }

    /**
     * Test having capabilities
     *
     * @param string[] $capabilities         capabilities
     * @param string[] $requiredCapabilities required capabilities
     * @param bool     $result               result
     *
     * @throws Exception
     *
     * @testWith [[], [], true]
     *           [["a", "b", "c"], [], true]
     *           [["a"], ["a"], true]
     *           [["a", "b", "c"], ["a", "c"], true]
     *           [[], ["a", "b"], false]
     *           [["a", "b", "c"], ["b", "d"], false]
     *           [["a", "b"], ["c", "d"], false]
     */
    public function testHavingCapabilities($capabilities, $requiredCapabilities, $result)
    {
        $userAccess = new UserAccess(new DataSet([
            'capabilities' => $capabilities,
        ], ''));
        $this->assertEquals($result, $userAccess->hasCapabilities(...$requiredCapabilities));
    }

    /**
     * Test checking capabilities
     *
     * @param string[] $capabilities         capabilities
     * @param string[] $requiredCapabilities required capabilities
     * @param bool     $result               result
     *
     * @throws Exception
     *
     * @testWith [[], [], true]
     *           [["a", "b", "c"], [], true]
     *           [["a"], ["a"], true]
     *           [["a", "b", "c"], ["a", "c"], true]
     *           [[], ["a", "b"], false]
     *           [["a", "b", "c"], ["b", "d"], false]
     *           [["a", "b"], ["c", "d"], false]
     */
    public function testCheckingCapabilities($capabilities, $requiredCapabilities, $result)
    {
        $userAccess = new UserAccess(new DataSet([
            'capabilities' => $capabilities,
        ], ''));
        try {
            $userAccess->checkCapabilitiesOrNoAccess(...$requiredCapabilities);
            $this->assertTrue($result);
        } catch (UnauthorizedException $exception) {
            $this->assertEquals('User doesn\'t have required capabilities.', $exception->getMessage());
        }
    }

    /**
     * Test issued at
     *
     * @param array    $claims claims
     * @param int|null $result result
     *
     * @throws Exception
     *
     * @testWith [{"iat": 1234567890}, 1234567890]
     *           [{"iat": "abc"}, null]
     *           [{}, null]
     */
    public function testIssuedAt(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $date = $userAccess->getIssuedAt();
        $this->assertEquals($result, isset($date) ? $date->getTimestamp() : null);
    }

    /**
     * Test expires at
     *
     * @param array    $claims claims
     * @param int|null $result result
     *
     * @throws Exception
     *
     * @testWith [{"exp": 1234567890}, 1234567890]
     *           [{"exp": "abc"}, null]
     *           [{}, null]
     */
    public function testExpiresAt(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $date = $userAccess->getExpiresAt();
        $this->assertEquals($result, isset($date) ? $date->getTimestamp() : null);
    }

    /**
     * Test issuer
     *
     * @param array       $claims claims
     * @param string|null $result result
     *
     * @testWith [{"iss": "abc"}, "abc"]
     *           [{"iss": 123}, 123]
     *           [{}, null]
     */
    public function testIssuer(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getIssuer());
    }

    /**
     * Test audience
     *
     * @param array       $claims claims
     * @param string|null $result result
     *
     * @testWith [{"aud": "abc"}, "abc"]
     *           [{"aud": 123}, 123]
     *           [{}, null]
     */
    public function testAudience(array $claims, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getAudience());
    }

    /**
     * Test JWT claims
     *
     * @param array $claims claims
     *
     * @testWith [{"claim1": "a", "claim2": 2}]
     */
    public function testJwtClaims(array $claims)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($claims, $userAccess->getJwtClaims());
    }

    /**
     * Test JWT claim
     *
     * @param array  $claims       claims
     * @param string $name         name
     * @param mixed  $defaultValue default value
     * @param mixed  $result       result
     *
     * @testWith [{"claim1": "a", "claim2": 2}, "claim1", null, "a"]
     *           [{"claim1": "a", "claim2": 2}, "claim2", null, 2]
     *           [{"claim1": "a", "claim2": 2}, "claim2", 3, 2]
     *           [{"claim1": "a", "claim2": 2}, "claim3", "c", "c"]
     *           [{"claim1": "a", "claim2": 2}, "claim3", null, null]
     */
    public function testJwtClaim(array $claims, $name, $defaultValue, $result)
    {
        $userAccess = new UserAccess(new DataSet($claims, ''));
        $this->assertEquals($result, $userAccess->getJwtClaim($name, $defaultValue));
    }
}
