<?php

use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class AuthMiddlewareTest extends TestCase
{
    /** @var Request|MockObject */
    private $requestMock;

    /** @var ParamPack|MockObject */
    private $headersMock;

    /** @var ConfigurationService|MockObject */
    private $configMock;

    /** @before */
    public function setupMocks()
    {
        $this->requestMock = $this->createMock(Request::class);
        $this->headersMock = $this->createMock(ParamPack::class);
        $this->requestMock->headers = $this->headersMock;
        $this->configMock = $this->createMock(ConfigurationService::class);
    }

    /**
     * Test not existed authorization header
     *
     * @param string $headerValue header value
     *
     * @testWith [""]
     *           [null]
     */
    public function testNotExistedAuthorizationHeader($headerValue)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn($headerValue)
        ;

        $middleware = new AuthMiddleware($this->configMock, 'key1');
        $this->assertNull($middleware->getUserAccessIfExists($this->requestMock));
    }

    /**
     * Test invalid token with authorization header
     */
    public function testInvalidTokenWithAuthorizationHeader()
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('abc')
        ;
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([]))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willThrowException(new UnauthorizedException('exception from configuration service'))
        ;

        $middleware = new AuthMiddleware($this->configMock, 'key1');
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('exception from configuration service');
        $middleware->getUserAccessIfExists($this->requestMock);
    }

    /**
     * Test valid token with authorization header
     */
    public function testValidTokenWithAuthorizationHeader()
    {
        $claims = [
            'claim1' => 'a',
            'claim2' => 2,
        ];
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('abc')
        ;
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken($claims))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willReturn(null)
        ;

        $middleware = new AuthMiddleware($this->configMock, 'key1');
        $userAccess = $middleware->getUserAccessIfExists($this->requestMock);
        $this->assertEquals($claims, $userAccess->getJwtClaims());
    }

    /**
     * Test invalid token without authorization header
     */
    public function testInvalidTokenWithoutAuthorizationHeader()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([]))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willThrowException(new UnauthorizedException('exception from configuration service'))
        ;

        $middleware = new AuthMiddleware($this->configMock, 'key1');
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('exception from configuration service');
        $middleware->getUserOrNoAccess($this->requestMock);
    }

    /**
     * Test valid token without authorization header
     */
    public function testValidTokenWithoutAuthorizationHeader()
    {
        $claims = [
            'claim1' => 'a',
            'claim2' => 2,
        ];
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken($claims))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willReturn(null)
        ;

        $middleware = new AuthMiddleware($this->configMock, 'key1');
        $userAccess = $middleware->getUserOrNoAccess($this->requestMock);
        $this->assertEquals($claims, $userAccess->getJwtClaims());
    }

    /**
     * Get token
     *
     * @param array $claims claims
     *
     * @return Token\Plain
     */
    private function getToken(array $claims): Token\Plain
    {
        return new Token\Plain(
            new Token\DataSet([], ''),
            new Token\DataSet($claims, ''),
            Token\Signature::fromEmptyData(),
        );
    }
}
