<?php

namespace SimpleAuth\Middleware;

use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;
use SimpleAuth\Model\AuthItemInterface;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthItemsMiddleware extends AuthMiddlewareAbstract
{
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
        parent::__construct($parser, $signer, $validationData);
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
        $token = $this->getToken($request);
        if (!$token->hasClaim('iss')) {
            throw new UnauthorizedException('Authorization token has no issuer defined.');
        }
        $issuer = $token->getClaim('iss');
        foreach ($this->items as $item) {
            if ($item->getName() != $issuer) {
                continue;
            }
            $this->verifyAndValidate($token, $item->getKey());
            return $item;
        }

        throw new UnauthorizedException('Proper authorization token not found.');
    }
}
