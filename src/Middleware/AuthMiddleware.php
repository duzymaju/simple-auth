<?php

namespace SimpleAuth\Middleware;

use Exception;
use SimpleAuth\Model\UserAccess;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthMiddleware
{
    /** @var ConfigurationService */
    private $config;

    /** @var string */
    private $publicKey;

    /**
     * Construct
     *
     * @param ConfigurationService $config    config
     * @param string               $publicKey public key
     */
    public function __construct(ConfigurationService $config, $publicKey)
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
    public function getUserAccessIfExists(Request $request)
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
    public function getUserOrNoAccess(Request $request)
    {
        $token = $this->config->getToken($request);
        $this->config->verifyAndValidate($token, $this->publicKey);

        return new UserAccess($token->claims());
    }
}
