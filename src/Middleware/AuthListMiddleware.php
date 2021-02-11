<?php

namespace SimpleAuth\Middleware;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\UserAccess;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthListMiddleware extends AuthMiddlewareAbstract
{
    /** @var string[] */
    private $publicKeys;

    /**
     * Construct
     *
     * @param Parser         $parser         parser
     * @param Signer         $signer         signer
     * @param ValidationData $validationData validation data
     * @param string[]       $publicKeys     public keys
     */
    public function __construct(Parser $parser, Signer $signer, ValidationData $validationData, array $publicKeys)
    {
        parent::__construct($parser, $signer, $validationData);
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
    public function getClaimsOrNoAccess(Request $request)
    {
        $token = $this->getToken($request);
        foreach ($this->publicKeys as $publicKey) {
            if ($this->isVerifiedAndValidated($token, $publicKey)) {
                $userAccess = new UserAccess($token->getClaims());
                return $userAccess->getJwtClaims();
            }
        }

        throw new UnauthorizedException('Public key which could positively verify authorization token not found.');
    }
}
