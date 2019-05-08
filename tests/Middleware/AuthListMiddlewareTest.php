<?php

use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthListMiddleware;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class AuthListMiddlewareTest extends TestCase
{
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
     * @param string|null $token   token
     * @param string      $message message
     *
     * @throws UnauthorizedException
     *
     * @testWith [null, "No authorization token."]
     *           ["", "No authorization token."]
     *           ["a b c", "Authorization token incorrect."]
     *           ["Bearer", "Authorization token incorrect."]
     *           ["Bearer ", "Authorization token incorrect."]
     *           ["Bearer jwt abc", "Authorization token incorrect."]
     */
    public function testUnknownToken($token, $message)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn($token)
        ;

        $middleware = new AuthListMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, []);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage($message);
        $middleware->getClaimsOrNoAccess($this->requestMock);
    }

    /**
     * Test not verified token
     *
     * @throws UnauthorizedException
     */
    public function testNotVerifiedToken()
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthListMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, [
            'public_key_1', 'public_key_2',
        ]);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->expects($this->exactly(2))
            ->method('verify')
            ->will($this->returnCallback(function ($signer, $publicKey) {
                unset($signer);
                switch ($publicKey) {
                    case 'public_key_1': return false;
                    case 'public_key_2': return true;
                    default: return false;
                }
            }))
        ;
        $this->tokenMock
            ->expects($this->exactly(1))
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(false)
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Public key which could positively verify authorization token not found.');
        $middleware->getClaimsOrNoAccess($this->requestMock);
    }

    /**
     * Test getting claims
     *
     * @throws UnauthorizedException
     */
    public function testGettingClaims()
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthListMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, [
            'public_key_1', 'public_key_2',
        ]);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->expects($this->exactly(2))
            ->method('verify')
            ->will($this->returnCallback(function ($signer, $publicKey) {
                unset($signer);
                switch ($publicKey) {
                    case 'public_key_1': return false;
                    case 'public_key_2': return true;
                    default: return false;
                }
            }))
        ;
        $this->tokenMock
            ->expects($this->exactly(1))
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(true)
        ;
        $claims = [
            'a' => 1,
            'b' => 2,
            'c' => 3,
        ];
        $this->tokenMock
            ->method('getClaims')
            ->willReturn(array_map(function ($key, $value) {
                return new TestClaim614($key, $value);
            }, array_keys($claims), array_values($claims)))
        ;
        $this->assertEquals($claims, $middleware->getClaimsOrNoAccess($this->requestMock));
    }
}

class TestClaim614 implements Claim
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
