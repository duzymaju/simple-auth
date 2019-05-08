<?php

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
            'iat' => 0,
            'exp' => 0,
            'capabilities' => $capabilities,
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
            'iat' => 0,
            'exp' => 0,
            'capabilities' => $capabilities,
        ]);
        try {
            $userAccess->checkCapabilitiesOrNoAccess(...$requiredCapabilities);
            $this->assertTrue($result);
        } catch (UnauthorizedException $exception) {
            $this->assertEquals('User doesn\'t have required capabilities.', $exception->getMessage());
        }
    }
}
