<?php

/**
 * This file is part of the AMFWebServicesSecurityBundle package.
 *
 * (c) Amine Fattouch <http://github.com/fattouchsquall>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AMF\WebServicesSecurityBundle\Security\Encoder;

use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Encoder\BasePasswordEncoder;

/**
 * Encode password for wsse.
 *
 * @package AMFWebServicesSecurityBundle
 * @author Amine Fattouch <amine.fattouch@gmail.com>
 */
class WssePasswordEncoder extends BasePasswordEncoder
{
    /**
     * @var string
     */
    protected $algorithm;
    
    /**
     * @var boolean
     */
    protected $encodeHashAsBase64;
    
    
    /**
     * Constructor class.
     *
     * @param string  $algorithm          The digest algorithm to use.
     * @param boolean $encodeHashAsBase64 Whether to base64 encode the password hash.
     */
    public function __construct($algorithm = 'sha1', $encodeHashAsBase64 = true)
    {
        $this->algorithm          = $algorithm;
        $this->encodeHashAsBase64 = $encodeHashAsBase64;
    }

    /**
     * {@inheritdoc}
     */
    public function encodePassword($raw, $salt)
    {
        if ($this->isPasswordTooLong($raw)) {
            throw new BadCredentialsException('Invalid password.');
        }

        if (!in_array($this->algorithm, hash_algos(), true)) {
            throw new \LogicException(sprintf('The algorithm "%s" is not supported.', $this->algorithm));
        }

        $salted = $this->mergePasswordAndSalt($raw, $salt);
        $digest = hash($this->algorithm, $salted, true);

        return $this->encodeHashAsBase64 ? base64_encode($digest) : bin2hex($digest);
    }

    /**
     * {@inheritdoc}
     */
    public function isPasswordValid($encoded, $raw, $salt)
    {
        return !$this->isPasswordTooLong($raw) && $this->comparePasswords($encoded, $this->encodePassword($raw, $salt));
    }
    
    /**
     * Merges a password and a salt.
     *
     * @param string $password The password to be used.
     * @param string $salt     The salt to be used.
     *
     * @return string
     */
    protected function mergePasswordAndSalt($password, $salt)
    {
        if (empty($salt)) {
            return $password;
        }

        return $salt.$password;
    }
}
