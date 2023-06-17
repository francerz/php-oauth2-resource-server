<?php

namespace Francerz\OAuth2\ResourceServer;

use Francerz\OAuth2\OAuth2ErrorException;
use Francerz\OAuth2\OAuth2Exception;
use LogicException;

class MissingRequestAuthorizationHeaderException extends OAuth2Exception
{
    public function __construct(
        $message = "Missing request authorization header",
        $code = 0,
        \Throwable $previous = null
    ) {
        parent::__construct($message, $code, $previous);
    }
}
