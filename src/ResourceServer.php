<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\Http\Utils\Headers\AbstractAuthorizationHeader;
use Francerz\Http\Utils\MessageHelper;
use Francerz\OAuth2\ServerAccessToken;
use Francerz\PowerData\Functions;
use LogicException;
use Psr\Http\Message\RequestInterface;
use RuntimeException;

class ResourceServer
{
    private $findAccessTokenHandler;
    private $accessToken;

    /**
     * Undocumented function
     *
     * @param callable $handler Signature (AbstractAuthorizationHeader $authHeader) : ?ServerAccessToken
     * @return void
     */
    public function setFindAccessTokenHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AbstractAuthorizationHeader::class], ServerAccessToken::class)) {
            throw new LogicException(
                'findAccessTokenHandler signature MUST be: '.
                '(AbstractAuthorizationHeader $authHeader) : ?ServerAccessToken'
            );
        }
        $this->findAccessTokenHandler = $handler;
    }

    /**
     * @deprecated 0.2.2
     *
     * @param RequestInterface $request
     * @param array $scopes
     * @return boolean
     */
    public function isValidScope(RequestInterface $request, array $scopes = []) : bool
    {
        $accessToken = $this->getAccessToken($request);
        if (is_null($accessToken)) {
            throw new RuntimeException('Not access token found.');
        }
        return $accessToken->matchAnyScope($scopes);
    }

    public function getAccessToken(RequestInterface $request) : ?ServerAccessToken
    {
        if (isset($this->accessToken)) {
            return $this->accessToken;
        }

        if (!is_callable($this->findAccessTokenHandler)) {
            throw new LogicException('Callable findAccessTokenHandler not found.');
        }

        $authHeader = MessageHelper::getFirstAuthorizationHeader($request);
        if (is_null($authHeader)) {
            throw new RuntimeException('Missing request Authorization header.');
        }

        $this->accessToken = call_user_func($this->findAccessTokenHandler, $authHeader);

        return $this->accessToken;
    }
}