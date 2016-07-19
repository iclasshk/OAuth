<?php

namespace JoakimKejser\OAuth;

/**
 * A consumer.
 *
 * @package JoakimKejser\OAuth
 */
class Consumer implements ConsumerInterface
{
    /**
     * The key of the consumer.
     *
     * @var string
     */
    private $key;

    /**
     * The secret of the consumer.
     *
     * @var string
     */
    private $secret;

    /**
     * Consumer constructor.
     *
     * @param $key
     * @param $secret
     */
    public function __construct($key, $secret)
    {
        $this->key = $key;
        $this->secret = $secret;

    }

    /**
     * Gets the key of the consumer.
     *
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * Gets the secret of the consumer.
     *
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}