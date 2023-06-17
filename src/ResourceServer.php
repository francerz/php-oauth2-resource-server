<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\ServerAccessToken;
use Psr\Http\Message\RequestInterface;

class ResourceServer
{
    private $accessTokenFinder;

    public function __construct(AccessTokenFinderInterface $finder)
    {
        $this->accessTokenFinder = $finder;
    }

    public function getAccessTokenFromRequest(RequestInterface $request): ?ServerAccessToken
    {
        $authHeaders = $request->getHeader('Authorization');
        if (empty($authHeaders)) {
            throw new MissingRequestAuthorizationHeaderException();
        }

        foreach ($authHeaders as $auth) {
            $parts = explode(' ', $auth);
            $at = $this->accessTokenFinder->findAccessToken($parts[0] ?? '', $parts[1] ?? '');
            if (isset($at)) {
                return $at;
            }
        }
        return null;
    }
}
