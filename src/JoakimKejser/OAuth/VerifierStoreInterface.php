<?php

namespace JoakimKejser\OAuth;

/**
 * An interface for the verifier store.
 *
 * @package JoakimKejser\OAuth
 */
interface VerifierStoreInterface
{
    /**
     * Stores a verifier for a token.
     *
     * @param TokenInterface|string $token The token associated to the verifier.
     * @param string $verifier The verifier string.
     * @return void
     */
    public function storeVerifier($token, $verifier);

    /**
     * Verifies a verifier.
     *
     * @param TokenInterface|string $token The token to verify.
     * @param string $verifier The verifier string.
     * @return bool Whether the token is valid.
     */
    public function verify($token, $verifier);

    /**
     * Removes a verifier from the store.
     *
     * @param TokenInterface|string $token The token associated to the verifier.
     * @param string $verifier The verifier string.
     * @return void
     */
    public function removeVerifier($token, $verifier);
}