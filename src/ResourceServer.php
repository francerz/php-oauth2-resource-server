<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\Http\Headers\AbstractAuthorizationHeader;
use Francerz\Http\Tools\MessageHelper;
use Francerz\OAuth2\ServerAccessToken;
use Francerz\PowerData\Functions;
use LogicException;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use SebastianBergmann\Environment\Runtime;

class ResourceServer
{
    private $findAccessTokenHandler;

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

    public function isValidScope(RequestInterface $request, array $scopes = []): bool
    {
        if (empty($scopes)) {
            return true;
        }
        if (!is_callable($this->findAccessTokenHandler)) {
            throw new LogicException('Callable findAccessTokenHandler not found.');
        }

        $authHeader = MessageHelper::getFirstAuthorizationHeader($request);

        if (is_null($authHeader)) {
            throw new RuntimeException('Missing request Authorization header.');
        }

        $accessToken = call_user_func($this->findAccessTokenHandler, $authHeader);

        if (is_null($accessToken)) {
            throw new RuntimeException('Cannot access protected resource.');
        }

        $intersects = array_intersect($scopes, explode(' ', $accessToken->getScope()));
        if (empty($intersects)) {
            return false;
        }
        return true;
    }
}