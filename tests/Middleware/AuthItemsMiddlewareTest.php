<?php

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Model\AuthItemInterface;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class AuthItemsMiddlewareTest extends TestCase
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

        $middleware = new AuthItemsMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, []);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage($message);
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test not found token
     *
     * @param string[] $issuers issuers
     *
     * @throws UnauthorizedException
     *
     * @testWith [[]]
     *           [["invalid_issuer1", "invalid_issuer2", "invalid_issuer3"]]
     */
    public function testNotFoundToken(array $issuers)
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $items = array_map(function ($issuer) {
            return new AuthItem($issuer, '');
        }, $issuers);
        $middleware = new AuthItemsMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, $items);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('getClaim')
            ->with('iss')
            ->willReturn('valid_issuer')
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Proper authorization token not found.');
        $middleware->getAuthItem($this->requestMock);
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

        $middleware = new AuthItemsMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, [
            new AuthItem('valid_issuer', 'issuer_key'),
        ]);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('getClaim')
            ->with('iss')
            ->willReturn('valid_issuer')
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'issuer_key')
            ->willReturn(false)
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization token not verified.');
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test invalid token
     *
     * @throws UnauthorizedException
     */
    public function testInvalidToken()
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $middleware = new AuthItemsMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, [
            new AuthItem('valid_issuer', 'issuer_key'),
        ]);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('getClaim')
            ->with('iss')
            ->willReturn('valid_issuer')
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'issuer_key')
            ->willReturn(true)
        ;
        $this->tokenMock
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(false)
        ;
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization token invalid.');
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test item selected
     *
     * @throws UnauthorizedException
     */
    public function testItemSelected()
    {
        $this->headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn('Bearer jwt')
        ;

        $authItem = new AuthItem('valid_issuer', 'issuer_key');
        $middleware = new AuthItemsMiddleware($this->parserMock, $this->signerMock, $this->validationDataMock, [
            $authItem,
        ]);
        $this->parserMock
            ->method('parse')
            ->with('jwt')
            ->willReturn($this->tokenMock)
        ;
        $this->tokenMock
            ->method('getClaim')
            ->with('iss')
            ->willReturn('valid_issuer')
        ;
        $this->tokenMock
            ->method('verify')
            ->with($this->signerMock, 'issuer_key')
            ->willReturn(true)
        ;
        $this->tokenMock
            ->method('validate')
            ->with($this->validationDataMock)
            ->willReturn(true)
        ;
        $this->assertEquals($authItem, $middleware->getAuthItem($this->requestMock));
    }
}

class AuthItem implements AuthItemInterface
{
    /** @var string */
    private $name;

    /** @var string */
    private $key;

    /**
     * Construct
     *
     * @param string $name name
     * @param string $key  key
     */
    public function __construct($name, $key)
    {
        $this->name = $name;
        $this->key = $key;
    }

    /**
     * Get name
     *
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * Get key
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }
}
