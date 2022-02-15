<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\ServerAccessToken;

interface ClientAccessTokenFinderInterface
{
    public function findClientAccessToken(
        string $tokenType,
        string $token
    ): ?ServerAccessToken;
}
