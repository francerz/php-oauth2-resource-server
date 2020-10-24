<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\Http\Headers\AbstractAuthorizationHeader;
use Francerz\Http\Tools\MessageHelper;
use Francerz\OAuth2\AccessToken;
use Francerz\PowerData\Functions;
use LogicException;
use Psr\Http\Message\RequestInterface;

class ResourceServer
{
    private $findAccessTokenHandler;

    /**
     * Undocumented function
     *
     * @param callable $handler Signature (AbstractAuthorizationHeader $authHeader) : ?AccessToken
     * @return void
     */
    public function setFindAccessTokenHandler(callable $handler)
    {
        if (!Functions::testSignature($handler, [AbstractAuthorizationHeader::class], AccessToken::class)) {
            throw new LogicException(
                'findAccessTokenHandler signature MUST be: '.
                '(AbstractAuthorizationHeader $authHeader) : ?AccessToken'
            );
        }
        $this->findAccessTokenHandler = $handler;
    }

    public function isValidScope(RequestInterface $request, array $scopes = []): bool
    {
        if (empty($scopes)) {
            return true;
        }
        if (!is_callable($this->findAccessTokenHandler)) {
            throw new LogicException('Callable findAccessTokenHandler not found.');
        }
        $authHeader = MessageHelper::getFirstAuthorizationHeader($request);
        $accessToken = call_user_func($this->findAccessTokenHandler, $authHeader);

        $intersects = array_intersect($scopes, explode(' ', $accessToken->getScope()));
        
        if (empty($intersects)) {
            return false;
        }

        return true;
    }
}