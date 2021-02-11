<?php

namespace SimpleAuth\Middleware;

use BadMethodCallException;
use InvalidArgumentException;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

abstract class AuthMiddlewareAbstract
{
    /** @var Parser */
    protected $parser;

    /** @var Signer */
    protected $signer;

    /** @var ValidationData */
    protected $validationData;

    /**
     * Construct
     *
     * @param Parser         $parser         parser
     * @param Signer         $signer         signer
     * @param ValidationData $validationData validation data
     */
    public function __construct(Parser $parser, Signer $signer, ValidationData $validationData)
    {
        $this->parser = $parser;
        $this->signer = $signer;
        $this->validationData = $validationData;
    }

    /**
     * Get token
     *
     * @param Request $request request
     *
     * @return Token
     *
     * @throws UnauthorizedException
     */
    protected function getToken(Request $request)
    {
        $header = $request->headers->getString('authorization');
        if (empty($header)) {
            throw new UnauthorizedException('No authorization token.');
        }
        $headerParts = explode(' ', $header);
        if (count($headerParts) !== 2 || $headerParts[0] !== 'Bearer' || empty($headerParts[1])) {
            throw new UnauthorizedException('Authorization token incorrect.');
        }

        return $this->parser->parse($headerParts[1]);
    }

    /**
     * Verify and validate
     *
     * @param Token  $token token
     * @param string $key   key
     *
     * @throws UnauthorizedException
     */
    protected function verifyAndValidate(Token $token, $key)
    {
        try {
            $isTokenVerified = $token->verify($this->signer, $key);
        } catch (BadMethodCallException $exception) {
            throw new UnauthorizedException('Authorization token not signed.');
        }
        if (!$isTokenVerified) {
            throw new UnauthorizedException('Authorization token not verified.');
        }
        try {
            $isTokenValid = $token->validate($this->validationData);
        } catch (InvalidArgumentException $exception) {
            throw new UnauthorizedException('Authorization key invalid.');
        }
        if (!$isTokenValid) {
            throw new UnauthorizedException('Authorization token invalid.');
        }
    }

    /**
     * Is verified and validated
     *
     * @param Token  $token token
     * @param string $key   key
     *
     * @return bool
     */
    protected function isVerifiedAndValidated(Token $token, $key)
    {
        try {
            $this->verifyAndValidate($token, $key);
        } catch (UnauthorizedException $exception) {
            return false;
        }

        return true;
    }
}
