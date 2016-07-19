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
}
