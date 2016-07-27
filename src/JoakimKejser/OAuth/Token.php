<?php
namespace JoakimKejser\OAuth;

class Token implements TokenInterface {
    /**
     * @var string The token.
     */
    private $token;

    /**
     * @var string The token secret.
     */
    private $secret;

    /**
     * Token constructor.
     * @param $token string The token key.
     * @param $secret string The token secret.
     */
    public function __construct($token, $secret)
    {
        $this->token = $token;
        $this->secret = $secret;
    }

    /**
     * generates the basic string serialization of a token that a server
     * would respond to request_token and access_token calls with
     */
    public function toString()
    {
        return "oauth_token=" .
        Util::urlencodeRfc3986($this->token) .
        "&oauth_token_secret=" .
        Util::urlencodeRfc3986($this->secret);
    }

    public function __toString()
    {
        return $this->toString();
    }

    /**
     * Returns the token string.
     *
     * @return string
     */
    public function getToken()
    {
        return $this->token;
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

    /**
     * Returns the token string.
     *
     * @deprecated Use getToken() instead.
     */
    public function getKey() {
        return $this->getToken();
    }
}