<?php

/**
 * This file is part of the AMFWebServicesSecurityBundle package.
 *
 * (c) Amine Fattouch <http://github.com/fattouchsquall>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AMF\WebServicesSecurityBundle\Security\Firewall;

use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

use AMF\WebServicesSecurityBundle\Security\Authentication\Token\WsseUserToken;

/**
 * The listener for authentication.
 *
 * @package AMFWebServicesSecurityBundle
 * @author Amine Fattouch <amine.fattouch@gmail.com>
 */
class WsseListener implements ListenerInterface
{
    /**
     * @var SecurityContextInterface
     */
    protected $securityContext;

    /**
     * @var AuthenticationManagerInterface
     */
    protected $authenticationManager;

    /**
     * @var string
     */
    protected $providerKey;


    /**
     * Constructor class.
     *
     * @param SecurityContextInterface       $securityContext       The service of security context.
     * @param AuthenticationManagerInterface $authenticationManager The service of authentication manager.
     * @param string                         $providerKey           The key of firewall.
     */
    public function __construct(SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager, $providerKey)
    {
        $this->securityContext       = $securityContext;
        $this->authenticationManager = $authenticationManager;
        $this->providerKey           = $providerKey;
    }

    /**
     * Handles the authentication for user.
     *
     * @param GetResponseEvent $event The response event.
     *
     * @throws AuthenticationException When the request is not authenticated.
     *
     * @return void
     */
    public function handle(GetResponseEvent $event)
    {
        $request = $event->getRequest();

        $wsseRegex = '/UsernameToken Username="([^"]+)", PasswordDigest="([^"]+)", Nonce="([^"]+)", Created="([^"]+)"/';
        if (!$request->headers->has('x-wsse') || 1 !== preg_match($wsseRegex, $request->headers->get('x-wsse'), $matches)) {
            return;
        }

        $token = new WsseUserToken($this->providerKey);
        $token->setUser($matches[1]);

        $token->setDigest($matches[2]);
        $token->setNonce($matches[3]);
        $token->setCreated($matches[4]);

        try {
            $authToken = $this->authenticationManager->authenticate($token);
            $this->securityContext->setToken($authToken);

            return;
        } catch (AuthenticationException $failed) {
            $failedMessage = 'WSSE Login failed for ' . $token->getUsername() . '.  Because: ' . $failed->getMessage();

            $token = $this->securityContext->getToken();
            if ($token instanceof WsseUserToken && $this->providerKey === $token->getProviderKey()) {
                 $this->securityContext->setToken(null);
            }

            // deny authentication with a '403 Forbidden' HTTP response
            $response = new Response();
            $response->setStatusCode(403);
            $event->setResponse($response);

            return;
        }

        // by default deny authorization
        $response = new Response();
        $response->setStatusCode(403);
        $event->setResponse($response);
    }
}
