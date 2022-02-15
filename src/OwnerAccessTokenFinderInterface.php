<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\ServerAccessToken;

interface OwnerAccessTokenFinderInterface
{
    public function findOwnerAccessToken(
        string $tokenType,
        string $token
    ): ?ServerAccessToken;
}
