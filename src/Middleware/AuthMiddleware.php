<?php

namespace SimpleAuth\Middleware;

use Exception;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\Jwt;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthMiddleware
{
    /** @var Parser */
    private $parser;

    /** @var Signer */
    private $signer;

    /** @var ValidationData */
    private $validationData;

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
        $this->parser = $parser;
        $this->signer = $signer;
        $this->validationData = $validationData;
        $this->publicKey = $publicKey;
    }

    /**
     * Get JWT if exists
     *
     * @param Request $request request
     *
     * @return Jwt|null
     *
     * @throws UnauthorizedException
     */
    public function getJwtIfExists(Request $request)
    {
        if (empty($request->headers->getString('authorization'))) {
            return null;
        }

        return $this->getJwtOrNoAccess($request);
    }

    /**
     * Get JWT or no access
     *
     * @param Request $request request
     *
     * @return Jwt|null
     *
     * @throws Exception
     * @throws UnauthorizedException
     */
    public function getJwtOrNoAccess(Request $request)
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
        if (!$token->verify($this->signer, $this->publicKey)) {
            throw new UnauthorizedException('Authorization token not verified.');
        }
        if (!$token->validate($this->validationData)) {
            throw new UnauthorizedException('Authorization token invalid.');
        }

        return new Jwt($token->getClaim('email'), $token->getClaim('capabilities'), $token->getClaim('iat'),
            $token->getClaim('exp'));
    }
}
