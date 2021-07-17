<?php

namespace SimpleAuth\Middleware;

use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthListMiddleware
{
    use MiddlewareTrait;

    /** @var ConfigurationService */
    private ConfigurationService $config;

    /** @var string[] */
    private array $publicKeys;

    /**
     * Construct
     *
     * @param ConfigurationService $config     config
     * @param string[]             $publicKeys public keys
     */
    public function __construct(ConfigurationService $config, array $publicKeys)
    {
        $this->config = $config;
        $this->publicKeys = $publicKeys;
    }

    /**
     * Get claims or no access
     *
     * @param Request $request request
     *
     * @return array
     *
     * @throws UnauthorizedException
     */
    public function getClaimsOrNoAccess(Request $request): array
    {
        $token = $this->config->getToken($this->getTokenString($request));
        foreach ($this->publicKeys as $publicKey) {
            if ($this->config->isVerifiedAndValidated($token, $publicKey)) {
                return $token
                    ->claims()
                    ->all()
                ;
            }
        }

        throw new UnauthorizedException('Public key which could positively verify authorization token not found.');
    }
}
