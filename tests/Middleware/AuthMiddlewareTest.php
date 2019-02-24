<?php

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Model\Jwt;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class AuthMiddlewareTest extends TestCase
{
    /** @var string */
    private $publicKey = 'public_key';

    /** @var Request|PHPUnit_Framework_MockObject_MockObject */
    private $requestMock;

    /** @var ParamPack|PHPUnit_Framework_MockObject_MockObject */
    private $headersMock;

    /** @var Parser|PHPUnit_Framework_MockObject_MockObject */
    private $parserMock;

    /** @var Signer|PHPUnit_Framework_MockObject_MockObject */
    private $signerMock;

    /** @var Token|PHPUnit_Framework_MockObject_MockObject */
    private $tokenMock;

    /** @var ValidationData|PHPUnit_Framework_MockObject_MockObject */
    private $validationDataMock;

    /** @before */
    public function setupMocks()
    {
        $this->requestMock = $this->createMock(Request::class);
        $this->headersMock = $this->requestMock->headers = $this->createMock(ParamPack::class);

        $this->parserMock = $this->createMock(Parser::class);
        $this->signerMock = $this->createMock(Signer::class);
        $this->tokenMock = $this->createMock(Token::class);
        $this->validationDataMock = $this->createMock(ValidationData::class);
    }

    /**
     * Test unknown token
     *
     * @param string      $method  method
     * @param string      $token   token
     * @param string|null $message message
     *
     * @testWith ["getJwtIfExists", null]
     *           ["getJwtIfExists", ""]
     *           ["getJwtIfExists", "a b c", "Authorization token incorrect."]
     *           ["getJwtIfExists", "Bearer", "Authorization token incorrect."]
     *           ["getJwtIfExists", "Bearer ", "Authorization token incorrect."]
     *           ["getJwtIfExists", "Bearer jwt abc", "Authorization token incorrect."]
     *           ["getJwtOrNoAccess", null, "No authorization token."]
     *           ["getJwtOrNoAccess", "", "No authorization token."]
     *           ["getJwtOrNoAccess", "a b c", "Authorization token incorrect."]
     *           ["getJwtOrNoAccess", "Bearer", "Authorization token incorrect."]
     *           ["getJwtOrNoAccess", "Bearer ", "Authorization token incorrect."]
     *           ["getJwtOrNoAccess", "Bearer jwt abc", "Authorization token incorrect."]
     */
    public function testUnknownToken($method, $token, $message = null)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn($token)
        ;

        $middleware = new AuthMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock,
            $this->publicKey);
        if (isset($message)) {
            $this->expectException(UnauthorizedException::class);
            $this->expectExceptionMessage($message);
            $middleware->$method($this->requestMock);
        } else {
            $this->assertNull($middleware->$method($this->requestMock));
        }
    }

    /**
     * Test not verified token
     *
     * @param string $method method
     *
     * @testWith ["getJwtIfExists"]
     *           ["getJwtOrNoAccess"]
     */
    public function testNotVerifiedToken($method)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock,
            $this->publicKey);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'public_key')
            ->willReturn(false)
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization token not verified.');
        $middleware->$method($this->requestMock);
    }

    /**
     * Test invalid token
     *
     * @param string $method method
     *
     * @testWith ["getJwtIfExists"]
     *           ["getJwtOrNoAccess"]
     */
    public function testInvalidToken($method)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock,
            $this->publicKey);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'public_key')
            ->willReturn(true)
        ;
        $this->tokenMock
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(false)
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization token invalid.');
        $middleware->$method($this->requestMock);
    }

    /**
     * Test returning JWT
     *
     * @param string        $method       method
     * @param string|null   $email        e-mail
     * @param string[]|null $capabilities capabilities
     * @param string|null   $issuedAt     issued at
     * @param string|null   $expiration   expiration
     *
     * @testWith ["getJwtIfExists", null, null, null, null]
     *           ["getJwtIfExists", "issuer@example.com", ["a", "b"], 1234567890, 1234567891]
     *           ["getJwtOrNoAccess", null, null, null, null]
     *           ["getJwtOrNoAccess", "issuer@example.com", ["a", "b"], 1234567890, 1234567891]
     */
    public function testReturningJwt($method, $email, $capabilities, $issuedAt, $expiration)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock,
            $this->publicKey);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'public_key')
            ->willReturn(true)
        ;
        $this->tokenMock
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(true)
        ;
        $this->tokenMock
            ->expects($this->exactly(4))
            ->method('getClaim')
            ->will($this->returnCallback(function ($param) use ($email, $capabilities, $issuedAt, $expiration) {
                switch ($param) {
                    case 'email': return $email;
                    case 'capabilities': return $capabilities;
                    case 'iat': return $issuedAt;
                    case 'exp': return $expiration;
                    default: return null;
                }
            }))
        ;
        /** @var Jwt $jwt */
        $jwt = $middleware->$method($this->requestMock);
        $this->assertEquals($email, $jwt->getEmail());
        $this->assertEquals(isset($capabilities) ? $capabilities : [], $jwt->getCapabilities());
        $jwtIssuedAt = $jwt->getIssuedAt();
        $this->assertEquals($issuedAt, isset($jwtIssuedAt) ? $jwtIssuedAt->getTimestamp() : null);
        $jwtExpiration = $jwt->getExpiration();
        $this->assertEquals($expiration, isset($jwtExpiration) ? $jwtExpiration->getTimestamp() : null);
    }
}
