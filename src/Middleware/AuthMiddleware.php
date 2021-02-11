<?php

namespace SimpleAuth\Middleware;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\UserAccess;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthMiddleware extends AuthMiddlewareAbstract
{
    /** @var string */
    private $publicKey;

    /**
     * Construct
     *
     * @param Parser         $parser         parser
     * @param Signer         $signer         signer
     * @param ValidationData $validationData validation data
     * @param string         $publicKey      public key
     */
    public function __construct(Parser $parser, Signer $signer, ValidationData $validationData, $publicKey)
    {
        parent::__construct($parser, $signer, $validationData);
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
        $token = $this->getToken($request);
        $this->verifyAndValidate($token, $this->publicKey);

        return new UserAccess($token->getClaims());
    }
}
