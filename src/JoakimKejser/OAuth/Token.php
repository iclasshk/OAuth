<?php
namespace JoakimKejser\OAuth;

class Token implements TokenInterface {
    private $key;
    private $secret;

    /**
     * Token constructor.
     * @param $key string The token key.
     * @param $secret string The token secret.
     */
    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * generates the basic string serialization of a token that a server
     * would respond to request_token and access_token calls with
     */
    public function toString()
    {
        return "oauth_token=" .
        Util::urlencodeRfc3986($this->key) .
        "&oauth_token_secret=" .
        Util::urlencodeRfc3986($this->secret);
    }

    public function __toString()
    {
        return $this->toString();
    }


    /**
     * Returns the token key.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Returns the token secret.
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}