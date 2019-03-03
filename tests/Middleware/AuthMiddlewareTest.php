<?php

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Model\UserAccess;
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
     * @testWith ["getUserAccessIfExists", null]
     *           ["getUserAccessIfExists", ""]
     *           ["getUserAccessIfExists", "a b c", "Authorization token incorrect."]
     *           ["getUserAccessIfExists", "Bearer", "Authorization token incorrect."]
     *           ["getUserAccessIfExists", "Bearer ", "Authorization token incorrect."]
     *           ["getUserAccessIfExists", "Bearer jwt abc", "Authorization token incorrect."]
     *           ["getUserOrNoAccess", null, "No authorization token."]
     *           ["getUserOrNoAccess", "", "No authorization token."]
     *           ["getUserOrNoAccess", "a b c", "Authorization token incorrect."]
     *           ["getUserOrNoAccess", "Bearer", "Authorization token incorrect."]
     *           ["getUserOrNoAccess", "Bearer ", "Authorization token incorrect."]
     *           ["getUserOrNoAccess", "Bearer jwt abc", "Authorization token incorrect."]
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
     * @testWith ["getUserAccessIfExists"]
     *           ["getUserOrNoAccess"]
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
     * @testWith ["getUserAccessIfExists"]
     *           ["getUserOrNoAccess"]
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
     * @param int|null      $issuedAt     issued at
     * @param int|null      $expiresAt    expires at
     *
     * @testWith ["getUserAccessIfExists", null, null, null, null]
     *           ["getUserAccessIfExists", "issuer@example.com", ["a", "b"], 1234567890, 1234567891]
     *           ["getUserOrNoAccess", null, null, null, null]
     *           ["getUserOrNoAccess", "issuer@example.com", ["a", "b"], 1234567890, 1234567891]
     */
    public function testReturningJwt($method, $email, $capabilities, $issuedAt, $expiresAt)
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
        $claims = [
            'capabilities' => $capabilities,
            'email' => $email,
            'exp' => $expiresAt,
            'iat' => $issuedAt,
        ];
        $this->tokenMock
            ->method('getClaims')
            ->willReturn($claims)
        ;
        /** @var UserAccess $userAccess */
        $userAccess = $middleware->$method($this->requestMock);
        $this->assertEquals($email, $userAccess->getEmail());
        $this->assertEquals(isset($capabilities) ? $capabilities : [], $userAccess->getCapabilities());
        $accessIssuedAt = $userAccess->getIssuedAt();
        $this->assertEquals($issuedAt, isset($accessIssuedAt) ? $accessIssuedAt->getTimestamp() : null);
        $accessExpiresAt = $userAccess->getExpiresAt();
        $this->assertEquals($expiresAt, isset($accessExpiresAt) ? $accessExpiresAt->getTimestamp() : null);
        $this->assertEquals($claims, $userAccess->getJwtClaims());
        $this->assertEquals($email, $userAccess->getJwtClaim('email'));
        $this->assertEquals('abc', $userAccess->getJwtClaim('notExistedClaim', 'abc'));
        $this->assertEquals(null, $userAccess->getJwtClaim('notExistedClaim'));

    }
}
