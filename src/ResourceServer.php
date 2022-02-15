<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\ServerAccessToken;
use LogicException;
use Psr\Http\Message\RequestInterface;
use RuntimeException;

class ResourceServer
{
    private $ownerAccessTokenFinder;
    private $clientAccessTokenFinder;

    private $ownerAccessToken;
    private $clientAccessToken;

    public function setOwnerAccessTokenFinder(OwnerAccessTokenFinderInterface $finder)
    {
        $this->ownerAccessTokenFinder = $finder;
    }

    public function setClientAccessTokenFinder(ClientAccessTokenFinderInterface $finder)
    {
        $this->clientAccessTokenFinder = $finder;
    }

    public function getOwnerAccessToken(RequestInterface $request): ?ServerAccessToken
    {
        if (isset($this->ownerAccessToken)) {
            return $this->ownerAccessToken;
        }

        if (!isset($this->ownerAccessTokenFinder)) {
            throw new LogicException('Missing Owner Access Token Finder.');
        }

        $authHeaders = $request->getHeader('Authorization');
        if (empty($authHeaders)) {
            throw new RuntimeException('Missing request Authorization header.');
        }

        foreach ($authHeaders as $header) {
            $parts = explode(' ', $header);
            $at = $this->ownerAccessTokenFinder->findOwnerAccessToken($parts[0] ?? '', $parts[1] ?? '');
            if (isset($at)) {
                $this->ownerAccessToken = $at;
                break;
            }
        }

        return $this->ownerAccessToken;
    }

    public function getClientAccessToken(RequestInterface $request): ?ServerAccessToken
    {
        if (isset($this->clientAccessToken)) {
            return $this->clientAccessToken;
        }

        if (!isset($this->clientAccessTokenFinder)) {
            throw new LogicException('Missing Client Access Token Finder.');
        }

        $authHeaders = $request->getHeader('Authorization');
        if (empty($authHeaders)) {
            throw new RuntimeException('Missing request Authorization header.');
        }

        foreach ($authHeaders as $header) {
            $parts = explode(' ', $header);
            $at = $this->clientAccessTokenFinder->findClientAccessToken($parts[0] ?? '', $parts[1] ?? '');
            if (isset($at)) {
                $this->clientAccessToken = $at;
                break;
            }
        }

        return $this->clientAccessToken;
    }
}
