<?php

namespace CommerceGuys\Guzzle\Oauth2\Tests;

use GuzzleHttp\Client;

abstract class TestBase extends \PHPUnit_Framework_TestCase
{
    /**
     * @param array $options
     *
     * @return \GuzzleHttp\ClientInterface
     */
    protected function getClient(array $options = [])
    {
        $server = new MockOAuth2Server();
        return new Client([
            'handler' => $server->getHandler()
        ] + $options);
    }
}
