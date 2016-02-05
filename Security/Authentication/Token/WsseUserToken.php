<?php

/**
 * This file is part of the AMFWebServicesSecurityBundle package.
 *
 * (c) Amine Fattouch <http://github.com/fattouchsquall>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AMF\WebServicesSecurityBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * The wsse token.
 *
 * @package AMFWebServicesSecurityBundle
 * @author Amine Fattouch <amine.fattouch@gmail.com>
 */
class WsseUserToken extends AbstractToken
{
    
    /**
     * @var string
     */
    protected $providerKey;
            
    /**
     * @var string
     */
    protected $created;
    
    /**
     * @var string
     */
    protected $digest;
    
    /**
     * @var string
     */
    protected $nonce;

    
    /**
     * Constructor class.
     *
     * @param string $providerKey The key for the provider.
     * @param array  $roles       The roles for the token.
     * @param string $created     The created attribute.
     * @param string $digest      The digest attribute.
     * @param string $nonce       The nonce attribute.
     */
    public function __construct($providerKey, array $roles = array(), $created = null, $digest = null, $nonce = null)
    {
        parent::__construct($roles);

        // if the user has roles, consider it authenticated
        $this->setAuthenticated(count($roles) > 0);

        $this->providerKey = $providerKey;
        $this->created     = $created;
        $this->digest      = $digest;
        $this->nonce       = $nonce;
    }

    /**
     * Getter for credentials.
     *
     * @return string
     */
    public function getCredentials()
    {
        return '';
    }
    
    /**
     * Setter for providerKey.
     *
     * @param string $providerKey The providerKey field for this class.
     *
     * @return void
     */
    public function setProviderKey($providerKey)
    {
        $this->providerKey = $providerKey;
    }
    
    /**
     * Getter for providerKey.
     *
     * @return string
     */
    public function getProviderKey()
    {
        return $this->providerKey;
    }
    
    /**
     * Setter for created.
     *
     * @param string $created The created field for this class.
     *
     * @return void
     */
    public function setCreated($created)
    {
        $this->created = $created;
    }

    /**
     * Getter for created.
     *
     * @return string
     */
    public function getCreated()
    {
        return $this->created;
    }
    
    /**
     * Setter for digest.
     *
     * @param string $digest The digest field for this class.
     *
     * @return void
     */
    public function setDigest($digest)
    {
        $this->digest = $digest;
    }

    /**
     * Getter for digest.
     *
     * @return string
     */
    public function getDigest()
    {
        return $this->digest;
    }
    
    /**
     * Setter for nonce.
     *
     * @param string $nonce The nonce field for this class.
     *
     * @return void
     */
    public function setNonce($nonce)
    {
        $this->nonce = $nonce;
    }

    /**
     * Getter for nonce.
     *
     * @return string
     */
    public function getNonce()
    {
        return $this->nonce;
    }
}
