<?php
namespace JoakimKejser\OAuth\NonceStore;

use JoakimKejser\OAuth\ConsumerInterface;
use JoakimKejser\OAuth\NonceStoreInterface;
use JoakimKejser\OAuth\TokenInterface;

class ArrayNonceStore implements NonceStoreInterface
{
    protected $nonces;

    public function __construct(array $nonces = array())
    {
        $this->nonces = $nonces;
    }

    public function lookup(ConsumerInterface $consumer, $nonce, $timestamp, TokenInterface $token = null)
    {
        if (array_key_exists($nonce, $this->nonces)) {
            list($storedConsumer, $storedTimestamp, $storedToken) = $this->nonces[$nonce];

            if ($storedConsumer === $consumer AND $storedTimestamp === $timestamp AND $storedToken === $token) {
                return true;
            }
        }

        $this->nonces[$nonce] = array($consumer, $timestamp, $token);

        return false;
    }
}
