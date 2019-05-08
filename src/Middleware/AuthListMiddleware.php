<?php

namespace SimpleAuth\Middleware;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\UserAccess;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthListMiddleware
{
    /** @var Parser */
    private $parser;

    /** @var Signer */
    private $signer;

    /** @var ValidationData */
    private $validationData;

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
        $this->parser = $parser;
        $this->signer = $signer;
        $this->validationData = $validationData;
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
        $header = $request->headers->getString('authorization');
        if (empty($header)) {
            throw new UnauthorizedException('No authorization token.');
        }

        $headerParts = explode(' ', $header);
        if (count($headerParts) !== 2 || $headerParts[0] !== 'Bearer' || empty($headerParts[1])) {
            throw new UnauthorizedException('Authorization token incorrect.');
        }

        $token = $this->parser->parse($headerParts[1]);
        foreach ($this->publicKeys as $publicKey) {
            if ($token->verify($this->signer, $publicKey) && $token->validate($this->validationData)) {
                $userAccess = new UserAccess($token->getClaims());
                return $userAccess->getJwtClaims();
            }
        }

        throw new UnauthorizedException('Public key which could positively verify authorization token not found.');
    }
}
