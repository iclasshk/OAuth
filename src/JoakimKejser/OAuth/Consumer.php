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
     * A list of localhost URLs.
     *
     * @
     */
    private static $LOCALHOST_URLS = array("127.0.0.1", "::1", "localhost");

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
     * An array of valid callback URLs. If the array is empty, assume all callback URLs are accepted.
     *
     * @var array
     */
    private $callbacks;

    /**
     * Consumer constructor.
     *
     * @param string $key The consumer key.
     * @param string $secret The consumer secret.
     * @param mixed $callbacks An array of callbacks, or a single callback URL string.
     */
    public function __construct($key, $secret, $callbacks = array())
    {
        $this->key = $key;
        $this->secret = $secret;
        if (is_string($callbacks)) {
            $this->callbacks = array($callbacks);
        } else {
            $this->callbacks = $callbacks;
        }
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

    /**
     * Gets all valid callback URLs for this consumer.
     *
     * @return array The array of valid callback URLs.
     */
    public function getValidCallbackUrls() {
        return $this->callbacks;
    }

    /**
     * Checks whether the callback URL is valid for this consumer.
     *
     * @param string $callback The callback to check for.
     * @param boolean $localhostValid Whether localhost-esque URLs are valid.
     * @return mixed
     */
    public function checkUrl($callback, $localhostValid = false)
    {
        // Check for URL sanity
        $callbackUrl = parse_url($callback);
        if (empty($callback) || !$callbackUrl) {
            return false; // malformed url
        }

        if ($localhostValid) {
            // Check localhost
            if (in_array($callbackUrl["host"], self::$LOCALHOST_URLS)) {
                return true;
            }
        }

        // TODO: Support globbing
        if (in_array($callback, $this->callbacks)) {
            return true;
        };

        return false;
    }
}