<?php

namespace SimpleAuth\Middleware;

use SimpleStructure\Http\Request;

trait MiddlewareTrait
{
    /** @var bool */
    private bool $acceptFromHeader = true;

    /** @var bool */
    private bool $acceptFromQueryString = false;

    /**
     * Accept tokens from header
     *
     * @param bool $acceptFromHeader accept from header
     *
     * @return self
     */
    public function acceptTokensFromHeader(bool $acceptFromHeader = true): self
    {
        $this->acceptFromHeader = $acceptFromHeader;

        return $this;
    }

    /**
     * Accept tokens from query string
     *
     * @param bool $acceptFromQueryString accept from query string
     *
     * @return self
     */
    public function acceptTokensFromQueryString(bool $acceptFromQueryString = true): self
    {
        $this->acceptFromQueryString = $acceptFromQueryString;

        return $this;
    }

    /**
     * Get token string
     *
     * @param Request $request request
     *
     * @return string|null
     */
    protected function getTokenString(Request $request): ?string
    {
        if ($this->acceptFromHeader) {
            $header = $request->headers->getString('authorization');
            if (!empty($header)) {
                $headerParts = explode(' ', $header);
                if (count($headerParts) !== 2 || $headerParts[0] !== 'Bearer' || empty($headerParts[1])) {
                    return null;
                }
                return $headerParts[1];
            }
        }

        if ($this->acceptFromQueryString) {
            $token = $request->query->getString('access_token');
            if (!empty($token)) {
                return $token;
            }
        }

        return null;
    }
}
