<?php

use PHPUnit\Framework\TestCase;
use SimpleAuth\Factory\AuthFactory;
use SimpleAuth\Middleware\AuthItemsMiddleware;
use SimpleAuth\Middleware\AuthListMiddleware;
use SimpleAuth\Middleware\AuthMiddleware;
use SimpleAuth\Provider\AuthHeaderProvider;

final class AuthFactoryTest extends TestCase
{
    /**
     * Test getting header provider
     */
    public function testGettingHeaderProvider()
    {
        $factory = new AuthFactory();
        $provider = $factory->getHeaderProvider('issuer1', 'privateKey1', 180);
        $this->assertInstanceOf(AuthHeaderProvider::class, $provider);
    }

    /**
     * Test getting auth middleware
     */
    public function testGettingAuthMiddleware()
    {
        $factory = new AuthFactory();
        $middleware = $factory->getAuthMiddleware('publicKey1', 'audience1', 'issuer1');
        $this->assertInstanceOf(AuthMiddleware::class, $middleware);
    }

    /**
     * Test getting auth list middleware
     */
    public function testGettingAuthListMiddleware()
    {
        $factory = new AuthFactory();
        $middleware = $factory->getAuthListMiddleware([], 'audience1', 'issuer1');
        $this->assertInstanceOf(AuthListMiddleware::class, $middleware);
    }

    /**
     * Test getting auth items middleware
     */
    public function testGettingAuthItemsMiddleware()
    {
        $factory = new AuthFactory();
        $middleware = $factory->getAuthItemsMiddleware([], 'audience1');
        $this->assertInstanceOf(AuthItemsMiddleware::class, $middleware);
    }
}
