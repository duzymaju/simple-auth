<?php

namespace SimpleAuth\Middleware;

use Lcobucci\JWT\Token\RegisteredClaims;
use SimpleAuth\Model\AuthItemInterface;
use SimpleAuth\Service\ConfigurationService;
use SimpleStructure\Exception\UnauthorizedException;
use SimpleStructure\Http\Request;

class AuthItemsMiddleware
{
    use MiddlewareTrait;

    /** @var ConfigurationService */
    private ConfigurationService $config;

    /** @var AuthItemInterface[] */
    private array $items;

    /**
     * Construct
     *
     * @param ConfigurationService $config config
     * @param AuthItemInterface[]  $items  items
     */
    public function __construct(ConfigurationService $config, array $items)
    {
        $this->config = $config;
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
    public function getAuthItem(Request $request): AuthItemInterface
    {
        $token = $this->config->getToken($this->getTokenString($request));
        $claims = $token->claims();
        if (!$claims->has(RegisteredClaims::ISSUER)) {
            throw new UnauthorizedException('Authorization token has no issuer defined.');
        }
        $issuer = $claims->get(RegisteredClaims::ISSUER);
        foreach ($this->items as $item) {
            if ($item->getName() != $issuer) {
                continue;
            }
            $this->config->verifyAndValidate($token, $item->getKey());
            return $item;
        }

        throw new UnauthorizedException('Proper authorization token not found.');
    }
}
