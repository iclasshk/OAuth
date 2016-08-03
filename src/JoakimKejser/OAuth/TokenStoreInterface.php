<?php
namespace JoakimKejser\OAuth;
use JoakimKejser\OAuth\Exception\InvalidConsumerException;
use JoakimKejser\OAuth\Exception\InvalidTokenException;

/**
 * An interface for a Token Store.
 *
 * @package JoakimKejser\OAuth
 */
interface TokenStoreInterface
{
    /**
     * Gets a token.
     *
     * @param ConsumerInterface $consumer The consumer this token belongs to.
     * @param int $tokenType The token type.
     * @param string $tokenField The token string to look up.
     * @return TokenInterface
     * @throws InvalidConsumerException
     * @throws InvalidTokenException
     * @see TokenType
     */
    public function getToken(ConsumerInterface $consumer, $tokenType, $tokenField);

    /**
     * Creates a new request token.
     *
     * @param ConsumerInterface $consumer The consumer.
     * @param array|string $callback All valid callback URLs.
     * @return TokenInterface
     * @throws InvalidConsumerException
     */
    public function newRequestToken(ConsumerInterface $consumer, $callback = null);

    /**
     * Creates a new access token.
     *
     * @param TokenInterface $requestToken The request token related to this request.
     * @param ConsumerInterface $consumer The consumer.
     * @return TokenInterface
     * @throws InvalidConsumerException
     * @throws InvalidTokenException If the request token is invalid.
     */
    public function newAccessToken(TokenInterface $requestToken, ConsumerInterface $consumer);

    /**
     * Removes a request token from the store.
     *
     * @param TokenInterface $requestToken The request token to remove.
     * @return void
     */
    public function removeRequestToken(TokenInterface $requestToken);

    /**
     * Removes an access token from the store.
     *
     * @param TokenInterface $accessToken The access token to remove.
     * @return void
     */
    public function removeAccessToken(TokenInterface $accessToken);
}
