<?php

use Lcobucci\JWT\Token;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthListMiddleware;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class AuthListMiddlewareTest extends TestCase
{
    /** @var Request|MockObject */
    private $requestMock;

    /** @var ConfigurationService|MockObject */
    private $configMock;

    /** @before */
    public function setupMocks()
    {
        $this->requestMock = $this->createMock(Request::class);
        $headersMock = $this->createMock(ParamPack::class);
        $this->requestMock->headers = $headersMock;
        $this->configMock = $this->createMock(ConfigurationService::class);
    }

    /**
     * Test empty public keys list
     */
    public function testEmptyPublicKeysList()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([]))
        ;

        $middleware = new AuthListMiddleware($this->configMock, []);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Public key which could positively verify authorization token not found.');
        $middleware->getClaimsOrNoAccess($this->requestMock);
    }

    /**
     * Test invalid tokens
     */
    public function testInvalidTokens()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([]))
        ;
        $this->configMock
            ->expects($this->exactly(4))
            ->method('isVerifiedAndValidated')
            ->willReturn(false)
        ;

        $middleware = new AuthListMiddleware($this->configMock, ['key4', 'key3', 'key1', 'key2']);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Public key which could positively verify authorization token not found.');
        $middleware->getClaimsOrNoAccess($this->requestMock);
    }

    /**
     * Test valid token
     */
    public function testValidToken()
    {
        $claims = [
            'claim1' => 'a',
            'claim2' => 2,
        ];
        $token = $this->getToken($claims);
        $this->configMock
            ->method('getToken')
            ->willReturn($token)
        ;
        $this->configMock
            ->method('isVerifiedAndValidated')
            ->withConsecutive([$token, 'key4'], [$token, 'key3'], [$token, 'key1'])
            ->willReturnOnConsecutiveCalls(false, false, true)
        ;

        $middleware = new AuthListMiddleware($this->configMock, ['key4', 'key3', 'key1', 'key2']);
        $this->assertEquals($claims, $middleware->getClaimsOrNoAccess($this->requestMock));
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
