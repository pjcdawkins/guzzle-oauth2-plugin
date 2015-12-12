<?php

namespace CommerceGuys\Guzzle\Oauth2;

use League\OAuth2\Client\Provider\AbstractProvider;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class OAuth2Middleware
{

    /** @var AbstractProvider */
    protected $provider;

    /** @var mixed */
    protected $grant;

    /**
     * Middleware that adds OAuth2 access tokens to requests when the 'oauth2'
     * request option is true.
     *
     * @return callable Returns a function that accepts the next handler.
     */
    public function getMiddleware()
    {
        return function (callable $handler) {
            return function (RequestInterface $request, array $options) use ($handler) {
                if (empty($options['oauth2'])) {
                    return $handler($request, $options);
                }

                // Add the token to the request.
                $request->withAddedHeader('Authorization', 'Bearer ' . $this->getAccessToken()->getToken());

                return $handler($request, $options)->then(
                    function (ResponseInterface $response) use ($request, $handler) {
                        $code = $response->getStatusCode();
                        if ($code === 401) {
                            // Retry the request.
                            // @todo
                        }

                        return $response;
                    }
                );
            };
        };
    }

    /**
     * @param \League\OAuth2\Client\Provider\AbstractProvider $provider
     */
    public function setProvider(AbstractProvider $provider)
    {
        $this->provider = $provider;
    }

    /**
     * @param mixed $grant
     */
    public function setGrant($grant)
    {
        $this->grant = $grant;
    }

    /**
     * @param bool $acquire
     *
     * @return \League\OAuth2\Client\Token\AccessToken
     */
    protected function getAccessToken($acquire = true)
    {
        if (!isset($this->token)) {
            if (!$acquire) {
                throw new \RuntimeException('No token available');
            }

            $this->token = $this->acquireAccessToken();
        }

        return $this->token;
    }

    /**
     * @return \League\OAuth2\Client\Token\AccessToken
     */
    protected function acquireAccessToken()
    {
        if (!isset($this->grant)) {
            throw new \RuntimeException('Grant not set');
        }

        return $this->provider->getAccessToken($this->grant);
    }
}
