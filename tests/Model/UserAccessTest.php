<?php

use Lcobucci\JWT\Claim;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Model\UserAccess;
use SimpleStructure\Exception\UnauthorizedException;

final class UserAccessTest extends TestCase
{
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
        $userAccess = new UserAccess([
            new TestClaim847('capabilities', $capabilities),
        ]);
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
        $userAccess = new UserAccess([
            new TestClaim847('capabilities', $capabilities),
        ]);
        try {
            $userAccess->checkCapabilitiesOrNoAccess(...$requiredCapabilities);
            $this->assertTrue($result);
        } catch (UnauthorizedException $exception) {
            $this->assertEquals('User doesn\'t have required capabilities.', $exception->getMessage());
        }
    }
}

class TestClaim847 implements Claim
{
    private $name;
    private $value;

    public function __construct($name, $value)
    {
        $this->name = $name;
        $this->value = $value;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function __toString()
    {
        return (string) $this->value;
    }

    public function jsonSerialize()
    {
        return null;
    }
}
