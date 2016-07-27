<?php
namespace JoakimKejser\OAuth;

/**
 * Interface ConsumerInterface
 * @package JoakimKejser\OAuth
 */
interface ConsumerInterface
{
    /**
     * Gets the key of the consumer.
     *
     * @return string
     */
    public function getKey();

    /**
     * Gets the secret of the consumer.
     *
     * @return string
     */
    public function getSecret();

    /**
     * Gets the consumer's valid callback URLs as an array.
     *
     * @return array The array of valid callback URLs.
     */
    public function getValidCallbackUrls();

    /**
     * Checks whether the callback URL is valid for this consumer.
     *
     * @param string $callback The callback to check for.
     * @param boolean $localhostValid Whether localhost-esque URLs are valid.
     * @return mixed
     */
    public function checkUrl($callback, $localhostValid = false);
}
