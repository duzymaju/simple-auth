<?php

use PHPUnit\Framework\TestCase;
use SimpleAuth\Middleware\MiddlewareTrait;
use SimpleStructure\Http\Request;
use SimpleStructure\Tool\ParamPack;

final class MiddlewareTraitTest extends TestCase
{
    /**
     * Test token string returning
     *
     * @param bool    $acceptFromHeader      accept from header
     * @param bool    $acceptFromQueryString accept from query string
     * @param ?string $headerValue           header value
     * @param ?string $queryStringValue      query stringValue
     * @param ?string $tokenString           token string
     *
     * @testWith [false, false, null, null, null]
     *           [true, true, null, null, null]
     *           [false, false, "Bearer abc", "def", null]
     *           [true, false, "Bearer abc", "def", "abc"]
     *           [false, true, "Bearer abc", "def", "def"]
     *           [true, true, "Bearer abc", "def", "abc"]
     *           [false, true, "abc", "def", "def"]
     *           [true, false, "abc", "def", null]
     *           [true, true, "abc", "def", null]
     */
    public function testTokenStringReturning(
        bool $acceptFromHeader, bool $acceptFromQueryString, ?string $headerValue, ?string $queryStringValue,
        ?string $tokenString
    ) {
        $requestMock = $this->createMock(Request::class);
        $headersMock = $this->createMock(ParamPack::class);
        $queryMock = $this->createMock(ParamPack::class);
        $requestMock->headers = $headersMock;
        $requestMock->query = $queryMock;
        $headersMock
            ->method('getString')
            ->with('authorization')
            ->willReturn($headerValue)
        ;
        $queryMock
            ->method('getString')
            ->with('access_token')
            ->willReturn($queryStringValue)
        ;

        $middleware = new Middleware();
        $middleware
            ->acceptTokensFromHeader($acceptFromHeader)
            ->acceptTokensFromQueryString($acceptFromQueryString)
        ;

        $this->assertEquals($middleware->getToken($requestMock), $tokenString);
    }
}

class Middleware
{
    use MiddlewareTrait;

    public function getToken(Request $request): ?string
    {
        return $this->getTokenString($request);
    }
}
