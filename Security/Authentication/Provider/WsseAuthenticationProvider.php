<?php

/**
 * This file is part of the AMFWebServicesSecurityBundle package.
 *
 * (c) Amine Fattouch <http://github.com/fattouchsquall>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AMF\WebServicesSecurityBundle\Security\Authentication\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Encoder\PasswordEncoderInterface;
use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Security\Core\Exception\NonceExpiredException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;

use AMF\WebServicesSecurityBundle\Security\Authentication\Token\WsseUserToken;

/**
 * The provider for authentication.
 *
 * @package AMFWebServicesSecurityBundle
 * @author Amine Fattouch <amine.fattouch@gmail.com>
 */
class WsseAuthenticationProvider implements AuthenticationProviderInterface
{
    
    /**
     * @var PasswordEncoderInterface
     */
    protected $encoder;
    
    /**
     * @var Filesystem
     */
    protected $filesystem;

    /**
     * @var UserProviderInterface
     */
    protected $userProvider;
    
    /**
     * @var string
     */
    protected $providerKey;
    
    /**
     * @var string
     */
    protected $lifetime;
    
    /**
     * @var string
     */
    protected $cacheDir;

    
    /**
     * Constructor class.
     *
     * @param PasswordEncoderInterface $encoder      The factory for the encoders of password.
     * @param Filesystem               $filesystem   The service for filesystem.
     * @param UserProviderInterface    $userProvider The provider of user.
     * @param string                   $providerKey  The key for the firewall's provider.
     * @param string                   $lifetime     The lifetime of token.
     * @param string                   $cacheDir     The cache directory for the nonces.
     */
    public function __construct(PasswordEncoderInterface $encoder = null,
                                Filesystem $filesystem = null,
                                UserProviderInterface $userProvider = null,
                                $providerKey = '',
                                $lifetime = '',
                                $cacheDir = null)
    {
        $this->encoder      = $encoder;
        $this->filesystem   = $filesystem;
        $this->userProvider = $userProvider;
        $this->providerKey  = $providerKey;
        $this->lifetime     = $lifetime;
        $this->cacheDir     = $cacheDir;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        $user = $this->userProvider->loadUserByUsername($token->getUsername());

        if ($user instanceof UserInterface) {
            if ("" === $token->getDigest()) {
                throw new BadCredentialsException('The presented password cannot be empty.');
            }
            
            if ($this->validateDigest($user, $token)) {
                $authenticatedToken = new WsseUserToken($user->getRoles());
                $authenticatedToken->setUser($user);

                return $authenticatedToken;
            }
        }

        throw new AuthenticationException('The WSSE authentication failed.');
    }

    /**
     * Checks whether this provider supports the given token.
     *
     * @param TokenInterface $token The current token.
     *
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return $token instanceof WsseUserToken && $token->getProviderKey() === $this->providerKey;
    }
    
    /**
     * Validates the password for wsse.
     *
     * @param UserInterface  $user  The provided user.
     * @param TokenInterface $token The created token.
     *
     * @return boolean
     *
     * @throws NonceExpiredException If the none is used again if the lifetime is expired.
     */
    protected function validateDigest(UserInterface $user, TokenInterface $token)
    {
        $created = $token->getCreated();
        $nonce   = $token->getNonce();

        // expired after the lifetime
        if (time() - strtotime($created) > $this->lifetime) {
            return false;
        }

        if ($this->filesystem->exists($this->cacheDir.'/'.$nonce) && file_get_contents($this->cacheDir.'/'.$nonce) + $this->lifetime > time()) {
            throw new NonceExpiredException('Previously used nonce detected');
        }
        
        // if cache directory does not exist it will be created
        if ($this->filesystem->exists($this->cacheDir) === false) {
            $this->filesystem->mkdir($this->cacheDir, 0777);
        }
        $this->filesystem->dumpFile($this->cacheDir.'/'.$nonce, time());
        
        $salt = base64_decode($nonce).$created;
        if (!$this->encoder->isPasswordValid($token->getDigest(), $user->getPassword(), $salt)) {
            throw new BadCredentialsException('The presented password is invalid.');
        }
        
        return true;
    }
}
