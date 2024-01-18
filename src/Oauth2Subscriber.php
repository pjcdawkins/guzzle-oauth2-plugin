<?php

namespace CommerceGuys\Guzzle\Oauth2;

use CommerceGuys\Guzzle\Oauth2\GrantType\GrantTypeInterface;
use CommerceGuys\Guzzle\Oauth2\GrantType\RefreshTokenGrantTypeInterface;
use GuzzleHttp\Event\BeforeEvent;
use GuzzleHttp\Event\ErrorEvent;
use GuzzleHttp\Event\RequestEvents;
use GuzzleHttp\Event\SubscriberInterface;
use GuzzleHttp\Exception\BadResponseException;
use GuzzleHttp\Message\ResponseInterface;

class Oauth2Subscriber implements SubscriberInterface
{

    /** @var AccessToken|null */
    protected $accessToken;
    /** @var AccessToken|null */
    protected $refreshToken;

    /** @var GrantTypeInterface */
    protected $grantType;
    /** @var RefreshTokenGrantTypeInterface */
    protected $refreshTokenGrantType;

    /** @var callable|null */
    protected $tokenSave;

    /** @var callable|null */
    protected $onRefreshStart;

    /** @var callable|null */
    protected $onRefreshEnd;

    /** @var callable|null */
    protected $onRefreshError;

    /** @var callable|null */
    protected $onStepUpAuthResponse;

    /**
     * Create a new Oauth2 subscriber.
     *
     * @param GrantTypeInterface             $grantType
     * @param RefreshTokenGrantTypeInterface $refreshTokenGrantType
     */
    public function __construct(GrantTypeInterface $grantType = null, RefreshTokenGrantTypeInterface $refreshTokenGrantType = null)
    {
        $this->grantType = $grantType;
        $this->refreshTokenGrantType = $refreshTokenGrantType;
    }

    /**
     * @inheritdoc
     */
    public function getEvents()
    {
        return [
            'before' => ['onBefore', RequestEvents::SIGN_REQUEST],
            'error' => ['onError', RequestEvents::EARLY],
        ];
    }

    /**
     * @inheritdoc
     */
    public function onError(ErrorEvent $event)
    {
        $response = $event->getResponse();
        if ($response && 401 == $response->getStatusCode()) {
            $request = $event->getRequest();
            if ($request->getConfig()->get('auth') == 'oauth2' && !$request->getConfig()->get('retried')) {
                if ($event->getResponse() && ($params = $this->parseStepUpAuthenticationResponse($response)) !== false) {
                    if (isset($this->onStepUpAuthResponse)) {
                        call_user_func($this->onStepUpAuthResponse, $params);
                    }
                } elseif ($token = $this->acquireAccessToken()) {
                    // Save the new token.
                    $this->accessToken = $token;
                    $this->refreshToken = $token->getRefreshToken();

                    // Retry the request.
                    $request->getConfig()->set('retried', true);
                    $event->intercept($event->getClient()->send($request));
                }
            }
        }
    }

    /**
     * Parses a step-up authentication response (RFC 9470).
     *
     * @param ResponseInterface $response
     *
     * @return false|array{acr_values: string[], max_age: ?int}
     *     False if this is not a step-up authentication response, or an
     *     array of auth parameters returned in the response.
     */
    protected function parseStepUpAuthenticationResponse(ResponseInterface $response)
    {
        $authHeader = $response->getHeader('WWW-Authenticate');
        if (stripos($authHeader, 'Bearer') !== false && strpos($authHeader, 'insufficient_user_authentication') !== false) {
            $parameters = ['acr_values' => [], 'max_age' => null];
            if (preg_match('#acr_values=("[^"]*"|[a-z0-9/+~_.-]*)#', $authHeader, $matches)) {
                $parameters['acr_values'] = explode(' ', trim($matches[1], '" '));
            }
            if (preg_match('#max_age=("?[0-9]+"?)#', $authHeader, $matches)) {
                $parameters['max_age'] = intval(trim($matches[1], '"'));
            }
            return $parameters;
        }
        return false;
    }

    /**
     * Get a new access token.
     *
     * @return AccessToken|null
     */
    protected function acquireAccessToken()
    {
        $accessToken = null;

        if ($this->refreshTokenGrantType) {
            // Get an access token using the stored refresh token.
            $currentRefreshToken = null;
            if ($this->refreshToken) {
                $currentRefreshToken = $this->refreshToken->getToken();
                $this->refreshTokenGrantType->setRefreshToken($currentRefreshToken);
            }
            if ($this->refreshTokenGrantType->hasRefreshToken()) {
                try {
                    if (isset($this->onRefreshStart)) {
                        $result = call_user_func($this->onRefreshStart, $currentRefreshToken);
                        if ($result instanceof AccessToken) {
                            return $result;
                        }
                    }
                    $accessToken = $this->refreshTokenGrantType->getToken();
                } catch (BadResponseException $e) {
                    if (isset($this->onRefreshError)) {
                        $accessToken = call_user_func($this->onRefreshError, $e);
                        if ($accessToken) {
                            return $accessToken;
                        }
                    }
                    throw $e;
                } finally {
                    if (isset($this->onRefreshEnd)) {
                        call_user_func($this->onRefreshEnd, $currentRefreshToken);
                    }
                }
            }
        }

        if (!$accessToken && $this->grantType) {
            // Get a new access token.
            $accessToken = $this->grantType->getToken();
        }

        if ($accessToken !== null && is_callable($this->tokenSave)) {
            call_user_func($this->tokenSave, $accessToken);
        }

        return $accessToken ?: null;
    }

    /**
     * Add the Authorization header to requests.
     *
     * @param BeforeEvent $event Event received
     */
    public function onBefore(BeforeEvent $event)
    {
        $request = $event->getRequest();
        if ($request->getConfig()->get('auth') == 'oauth2') {
            $token = $this->getAccessToken();
            if ($token !== null) {
                $request->setHeader('Authorization', 'Bearer ' . $token->getToken());
            }
        }
    }

    /**
     * Get the access token.
     *
     * @param bool $refresh Whether to refresh the token, if possible.
     *
     * @return AccessToken|null Oauth2 access token
     */
    public function getAccessToken($refresh = true)
    {
        if ($this->accessToken && $this->accessToken->isExpired()) {
            // The access token has expired.
            $this->accessToken = null;
        }

        if (null === $this->accessToken && $refresh) {
            // Try to acquire a new access token from the server.
            $this->accessToken = $this->acquireAccessToken();
            if ($this->accessToken) {
                $this->refreshToken = $this->accessToken->getRefreshToken();
            }
        }

        return $this->accessToken;
    }

    /**
     * Get the refresh token.
     *
     * @return AccessToken|null
     */
    public function getRefreshToken()
    {
        return $this->refreshToken;
    }

    /**
     * Set the access token.
     *
     * @param AccessToken|string $accessToken
     * @param string             $type
     * @param int                $expires
     */
    public function setAccessToken($accessToken, $type = null, $expires = null)
    {
        if (is_string($accessToken)) {
            $accessToken = new AccessToken($accessToken, $type, ['expires' => $expires]);
        } elseif (!$accessToken instanceof AccessToken) {
            throw new \InvalidArgumentException('Invalid access token');
        }
        $this->accessToken = $accessToken;
        $this->refreshToken = $accessToken->getRefreshToken();
    }

    /**
     * Set the refresh token.
     *
     * @param AccessToken|string $refreshToken The refresh token
     */
    public function setRefreshToken($refreshToken)
    {
        if (is_string($refreshToken)) {
            $refreshToken = new AccessToken($refreshToken, 'refresh_token');
        } elseif (!$refreshToken instanceof AccessToken) {
            throw new \InvalidArgumentException('Invalid refresh token');
        }
        $this->refreshToken = $refreshToken;
    }

    /**
     * Set a callback that will save a token whenever a new one is acquired.
     *
     * @param callable $tokenSave
     *   A callback accepting one argument (the AccessToken) that will save a
     *   token.
     */
    public function setTokenSaveCallback(callable $tokenSave)
    {
        $this->tokenSave = $tokenSave;
    }

    /**
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token being used if
     *   available (a string or null), and returns an AccessToken or null.
     */
    public function setOnRefreshStart(callable $callback)
    {
        $this->onRefreshStart = $callback;
    }

    /**
     * @param callable $callback
     *   A callback which accepts 1 argument, the refresh token which was used
     *   if available (a string or null).
     */
    public function setOnRefreshEnd(callable $callback)
    {
        $this->onRefreshEnd = $callback;
    }

    /**
     * Set a callback that will react to a refresh token error.
     *
     * @param callable $callback
     *   A callback which accepts one argument, the BadResponseException, and
     *   returns an AccessToken or null.
     */
    public function setOnRefreshError(callable $callback)
    {
      $this->onRefreshError = $callback;
    }

    /**
     * Set a callback that will react to a step-up authentication response (RFC 9470).
     *
     * @param callable $callback
     *   A callback which accepts one argument, an array of RFC 9470 auth
     *   parameters, containing the keys "acr_values" (an array of strings)
     *   and "max_age" (a positive integer or null).
     */
    public function setOnStepUpAuthResponse(callable $callback)
    {
        $this->onStepUpAuthResponse = $callback;
    }
}
