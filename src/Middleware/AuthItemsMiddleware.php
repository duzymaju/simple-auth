<?php

namespace SimpleAuth\Middleware;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\AuthItemInterface;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthItemsMiddleware
{
    /** @var Parser */
    private $parser;

    /** @var Signer */
    private $signer;

    /** @var ValidationData */
    private $validationData;

    /** @var AuthItemInterface[] */
    private $items;

    /**
     * Construct
     *
     * @param Parser              $parser         parser
     * @param Signer              $signer         signer
     * @param ValidationData      $validationData validation data
     * @param AuthItemInterface[] $items          items
     */
    public function __construct(Parser $parser, Signer $signer, ValidationData $validationData, array $items)
    {
        $this->parser = $parser;
        $this->signer = $signer;
        $this->validationData = $validationData;
        $this->items = $items;
    }

    /**
     * Get auth item
     *
     * @param Request $request request
     *
     * @return AuthItemInterface
     *
     * @throws UnauthorizedException
     */
    public function getAuthItem(Request $request)
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
        $issuer = $token->getClaim('iss');
        foreach ($this->items as $item) {
            if ($item->getName() != $issuer) {
                continue;
            }
            if (!$token->verify($this->signer, $item->getKey())) {
                throw new UnauthorizedException('Authorization token not verified.');
            }
            if (!$token->validate($this->validationData)) {
                throw new UnauthorizedException('Authorization token invalid.');
            }
            return $item;
        }

        throw new UnauthorizedException('Proper authorization token not found.');
    }
}
