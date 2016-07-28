<?php
namespace JoakimKejser\OAuth;
use JoakimKejser\OAuth\Exception\InvalidCallbackUrlException;

/**
 * Class Server
 * @package JoakimKejser\OAuth
 */
class Server
{
    /**
     * @var int seconds
     */
    protected $timestampThreshold = 300;

    /**
     * @var string
     */
    protected $version = '1.0';

    /**
     * @var array
     */
    protected $signatureMethods = array();

    /**
     * @var ConsumerStoreInterface
     */
    protected $consumerStore;
    /**
     * @var NonceStoreInterface
     */
    protected $nonceStore;

    /**
     * @var TokenStoreInterface
     */
    protected $tokenStore;

    /**
     * @var VerifierStoreInterface
     */
    protected $verifierStore;

    /**
     * Whether localhost is a valid callback domain.
     *
     * @var boolean
     */
    protected $localhostValid = false;

    /**
     * Constructor
     * @param OauthRequest $request
     * @param ConsumerStoreInterface $consumerStore
     * @param NonceStoreInterface $nonceStore
     * @param TokenStoreInterface $tokenStore
     * @param VerifierStoreInterface $verifierStore
     * @param boolean $localhostValid Whether localhost is a valid callback domain.
     */
    public function __construct(
        OauthRequest $request,
        ConsumerStoreInterface $consumerStore,
        NonceStoreInterface $nonceStore,
        TokenStoreInterface $tokenStore = null,
        VerifierStoreInterface $verifierStore = null,
        $localhostValid = false
    ) {
        $this->request = $request;
        $this->consumerStore = $consumerStore;
        $this->nonceStore = $nonceStore;
        $this->tokenStore = $tokenStore;
        $this->verifierStore = $verifierStore;
        $this->localhostValid = $localhostValid;
    }

    /**
     * Adds a signature method to the server object
     *
     * Adds the signature method to the supported signature methods
     *
     * @param SignatureMethod $signatureMethod
     */
    public function addSignatureMethod(SignatureMethod $signatureMethod)
    {
        $this->signatureMethods[$signatureMethod->getName()] = $signatureMethod;
    }

    /**
     * process a request_token request
     * @return array consumer, request token, and oauth callback on success
     */
    public function fetchRequestToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // no token required for the initial token request
        $token = null;

        $callback = $this->request->getParameter('oauth_callback');
        $this->checkCallbackUrl($consumer, $callback);
        $this->checkSignature($consumer, $token);

        $newToken = $this->tokenStore->newRequestToken($consumer, $callback);

        return array($consumer, $newToken, $callback);
    }

    /**
     * Fetches a request token response after authorization in a 3-legged OAuth request.
     * This method assumes that the token has been verified and authorized.
     *
     * @param TokenInterface|string $token The token to generate a verifier for.
     * @return string The verifier string.
     */
    public function fetchRequestVerifierResponse($token) {
        if ($token instanceof TokenInterface) {
            $token = $token->getToken();
        }

        $verifier = self::generateVerifier();
        $this->verifierStore->storeVerifier($token, $verifier);
        return $verifier;
    }

    /**
     * process an access_token request
     * @return array consumer, token, and verifier on success
     */
    public function fetchAccessToken()
    {
        $this->getVersion();

        $consumer = $this->getConsumer();

        // requires authorized request token
        $token = $this->getToken($consumer, TokenType::REQUEST);

        $this->checkSignature($consumer, $token);

        // Verify verifier (for OAuth 1.0a compliance)
        $verifier = $this->request->getParameter('oauth_verifier');
        $this->checkVerifier($token, $verifier);
        $newToken = $this->tokenStore->newAccessToken($token, $consumer, $verifier);

        return array($consumer, $newToken, $verifier);
    }

    /**
     * verify an api call, checks all the parameters
     * @return array consumer and token
     */
    public function verifyRequest()
    {
        $this->getVersion();
        $consumer = $this->getConsumer();
        $token = $this->getToken($consumer, TokenType::ACCESS);
        $this->checkSignature($consumer, $token);

        return array($consumer, $token);
    }

    /**
     * version 1
     */
    private function getVersion()
    {
        $version = $this->request->getParameter("oauth_version");
        if (!$version) {
            // Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present.
            // Chapter 7.0 ("Accessing Protected Ressources")
            $version = '1.0';
        }
        if ($version !== $this->version) {
            throw new Exception\VersionNotSupportedException();
        }

        return $version;
    }

    /**
     * figure out the signature with some defaults
     * @throws Exception\SignatureMethodMissingException
     * @throws Exception\SignatureMethodNotSupportedException
     * @return SignatureMethod
     */
    private function getSignatureMethod()
    {
        $signatureMethod = $this->request->getParameter("oauth_signature_method");

        if (!$signatureMethod) {
            // According to chapter 7 ("Accessing Protected Ressources") the signature-method
            // parameter is required, and we can't just fallback to PLAINTEXT
            throw new Exception\SignatureMethodMissingException();
        }

        if (!in_array($signatureMethod, array_keys($this->signatureMethods))) {
            throw new Exception\SignatureMethodNotSupportedException(
                "Signature method '$signatureMethod' not supported, try one of the following: " .
                implode(", ", array_keys($this->signatureMethods))
            );
        }

        return $this->signatureMethods[$signatureMethod];
    }

    /**
     * try to find the consumer for the provided request's consumer key
     * @throws Exception\ConsumerKeyMissingException
     * @throws Exception\InvalidConsumerException
     * @return ConsumerInterface
     */
    private function getConsumer()
    {
        $consumerKey = $this->request->getParameter("oauth_consumer_key");

        if (!$consumerKey) {
            throw new Exception\ConsumerKeyMissingException();
        }

        $consumer = $this->consumerStore->getConsumer($consumerKey);
        if (!$consumer) {
            throw new Exception\InvalidConsumerException();
        }

        return $consumer;
    }

    /**
     * try to find the token for the provided request's token key
     * @param ConsumerInterface $consumer
     * @param string $tokenType
     * @return mixed|null
     * @throws Exception\InvalidTokenException
     */
    private function getToken(ConsumerInterface $consumer, $tokenType = TokenType::ACCESS)
    {
        if ($this->tokenStore === null) {
            return null;
        }

        $tokenField = $this->request->getParameter('oauth_token');
        if (is_null($tokenField)) {
            return null;
        }

        $token = $this->tokenStore->getToken(
            $consumer,
            $tokenType,
            $tokenField
        );

        if (!$token) {
            throw new Exception\InvalidTokenException("Invalid $tokenType token: $tokenField");
        }

        return $token;
    }

    /**
     * all-in-one function to check the signature on a request
     * should guess the signature method appropriately
     * @param ConsumerInterface $consumer
     * @param TokenInterface $token
     * @throws Exception\InvalidSignatureException
     * @throws Exception\NonceAlreadyUsedException
     * @throws Exception\NonceMissingException
     * @throws Exception\SignatureMethodMissingException
     * @throws Exception\SignatureMethodNotSupportedException
     * @throws Exception\TimestampExpiredException
     * @throws Exception\TimestampMissingException
     */
    private function checkSignature(ConsumerInterface $consumer, TokenInterface $token = null)
    {
        // this should probably be in a different method
        $timestamp = $this->request->getParameter('oauth_timestamp');
        $nonce = $this->request->getParameter('oauth_nonce');

        $this->checkTimestamp($timestamp);
        $this->checkNonce($consumer, $nonce, $timestamp, $token);

        $signatureMethod = $this->getSignatureMethod();

        $signature = $this->request->getParameter('oauth_signature');
        $validSig = $signatureMethod->checkSignature(
            $signature,
            $this->request,
            $consumer,
            $token
        );

        if (!$validSig) {
            $exception = new Exception\InvalidSignatureException();
            $exception->setDebugInfo($this->request->getSignatureBaseString());
            throw $exception;
        }
    }

    /**
     * check that the timestamp is new enough
     * @param int $timestamp
     * @throws Exception\TimestampExpiredException
     * @throws Exception\TimestampMissingException
     */
    private function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            throw new Exception\TimestampMissingException();
        }

        // verify that timestamp is recentish
        $now = time();
        if (abs($now - $timestamp) > $this->timestampThreshold) {
            throw new Exception\TimestampExpiredException();
        }
    }

    /**
     * check that the nonce is not repeated
     * @param ConsumerInterface $consumer
     * @param string $nonce
     * @param int $timestamp
     * @param TokenInterface $token
     * @throws Exception\NonceAlreadyUsedException
     * @throws Exception\NonceMissingException
     */
    private function checkNonce(ConsumerInterface $consumer, $nonce, $timestamp, TokenInterface $token = null)
    {
        if (!$nonce) {
            throw new Exception\NonceMissingException();
        }

        // verify that the nonce is uniqueish
        $found = $this->nonceStore->lookup(
            $consumer,
            $nonce,
            $timestamp,
            $token
        );

        if ($found) {
            throw new Exception\NonceAlreadyUsedException();
        }
    }

    /**
     * Checks a token verifier against the token verifier store.
     *
     * @param TokenInterface $token
     * @param string $verifier
     * @return void
     * @throws Exception\VerifierMismatchException
     */
    private function checkVerifier(TokenInterface $token, $verifier) {
        if (!$this->verifierStore->verify($token->getToken(), $verifier)) {
            throw new Exception\VerifierMismatchException();
        }
    }

    /**
     * Checks whether the callback URL provided is a valid URL for this consumer.
     *
     * @param ConsumerInterface $consumer
     * @param $callbackUrl
     * @throws InvalidCallbackUrlException
     */
    private function checkCallbackUrl(ConsumerInterface $consumer, $callbackUrl) {
        if (!$consumer->checkUrl($callbackUrl, $this->localhostValid)) {
            throw new Exception\InvalidCallbackUrlException();
        }
    }

    /**
     * Generates a verifier string.
     *
     * @return string The verifier string.
     */
    private static function generateVerifier() {
        return sha1(random_bytes(32));
    }
}
