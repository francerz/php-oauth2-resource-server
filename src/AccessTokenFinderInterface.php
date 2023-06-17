<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\ServerAccessToken;

interface AccessTokenFinderInterface
{
    public function findAccessToken(
        string $tokenType,
        string $token
    ): ?ServerAccessToken;
}
