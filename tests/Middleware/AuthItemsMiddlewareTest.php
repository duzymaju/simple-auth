<?php

use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\RegisteredClaims;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Model\AuthItemInterface;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

final class AuthItemsMiddlewareTest extends TestCase
{
    /** @var Request|MockObject */
    private $requestMock;

    /** @var ConfigurationService|MockObject */
    private $configMock;

    /** @var Token|MockObject */
    private $tokenMock;

    /** @before */
    public function setupMocks()
    {
        $this->requestMock = $this->createMock(Request::class);
        $this->configMock = $this->createMock(ConfigurationService::class);
        $this->tokenMock = $this->createMock(Token::class);
    }

    /**
     * Test token without issuer
     */
    public function testTokenWithoutIssuer()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([]))
        ;

        $middleware = new AuthItemsMiddleware($this->configMock, []);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Authorization token has no issuer defined.');
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test token with unknown issuer
     */
    public function testTokenWithUnknownIssuer()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([
                RegisteredClaims::ISSUER => 'issuer1',
            ]))
        ;

        $middleware = new AuthItemsMiddleware($this->configMock, []);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('Proper authorization token not found.');
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test invalid token
     */
    public function testInvalidToken()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([
                RegisteredClaims::ISSUER => 'issuer1',
            ]))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willThrowException(new UnauthorizedException('exception from configuration service'))
        ;

        $selectedAuthItem = new AuthItem('issuer1', 'key1');
        $middleware = new AuthItemsMiddleware($this->configMock, [
            new AuthItem('issuer3', 'key3'),
            $selectedAuthItem,
            new AuthItem('issuer2', 'key2'),
        ]);
        $this->expectException(UnauthorizedException::class);
        $this->expectExceptionMessage('exception from configuration service');
        $middleware->getAuthItem($this->requestMock);
    }

    /**
     * Test valid token
     */
    public function testValidToken()
    {
        $this->configMock
            ->method('getToken')
            ->willReturn($this->getToken([
                RegisteredClaims::ISSUER => 'issuer1',
            ]))
        ;
        $this->configMock
            ->method('verifyAndValidate')
            ->willReturn(null)
        ;

        $selectedAuthItem = new AuthItem('issuer1', 'key1');
        $middleware = new AuthItemsMiddleware($this->configMock, [
            new AuthItem('issuer3', 'key3'),
            $selectedAuthItem,
            new AuthItem('issuer2', 'key2'),
        ]);
        $this->assertEquals($selectedAuthItem, $middleware->getAuthItem($this->requestMock));
    }

    /**
     * Get token
     *
     * @param array $claims claims
     *
     * @return Token\Plain
     */
    private function getToken(array $claims)
    {
        return new Token\Plain(
            new Token\DataSet([], ''),
            new Token\DataSet($claims, ''),
            Token\Signature::fromEmptyData(),
        );
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
