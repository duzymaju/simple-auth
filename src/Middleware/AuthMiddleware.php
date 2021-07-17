<?php

namespace SimpleAuth\Middleware;

use Exception;
use SimpleAuth\Model\UserAccess;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthMiddleware
{
    use MiddlewareTrait;

    /** @var ConfigurationService */
    private ConfigurationService $config;

    /** @var string */
    private string $publicKey;

    /**
     * Construct
     *
     * @param ConfigurationService $config    config
     * @param string               $publicKey public key
     */
    public function __construct(ConfigurationService $config, string $publicKey)
    {
        $this->config = $config;
        $this->publicKey = $publicKey;
    }

    /**
     * Get user access if exists
     *
     * @param Request $request request
     *
     * @return UserAccess|null
     *
     * @throws UnauthorizedException
     */
    public function getUserAccessIfExists(Request $request): ?UserAccess
    {
        if (empty($request->headers->getString('authorization'))) {
            return null;
        }

        return $this->getUserOrNoAccess($request);
    }

    /**
     * Get user or no access
     *
     * @param Request $request request
     *
     * @return UserAccess
     *
     * @throws Exception
     * @throws UnauthorizedException
     */
    public function getUserOrNoAccess(Request $request): UserAccess
    {
        $token = $this->config->getToken($this->getTokenString($request));
        $this->config->verifyAndValidate($token, $this->publicKey);

        return new UserAccess($token->claims());
    }
}
