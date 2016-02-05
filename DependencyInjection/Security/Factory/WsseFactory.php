<?php

/**
 * This file is part of the AMFWebServicesSecurityBundle package.
 *
 * (c) Amine Fattouch <http://github.com/fattouchsquall>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AMF\WebServicesSecurityBundle\DependencyInjection\Security\Factory;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\AbstractFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;

/**
 * The factory for security.
 *
 * @package AMFWebServicesSecurityBundle
 * @author Amine Fattouch <amine.fattouch@gmail.com>
 */
class WsseFactory extends AbstractFactory
{

    /**
     * Constructor class.
     */
    public function __construct()
    {
        $this->addOption('lifetime', 300);
    }
    
    /**
     * Returns the position for the firewall.
     *
     * @return string
     */
    public function getPosition()
    {
        return 'pre_auth';
    }

    /**
     * Getter for the key of firewall.
     *
     * @return string
     */
    public function getKey()
    {
        return 'wsse';
    }
    
    /**
     * Adds configuration of security.
     *
     * @param NodeDefinition $node The root node of wsse security.
     *
     * @return void
     */
    public function addConfiguration(NodeDefinition $node)
    {
        $node->children()
                ->scalarNode('lifetime')->defaultValue(300)->end()
                ->arrayNode('encoder')
                ->addDefaultsIfNotSet()
                    ->children()
                        ->scalarNode('algorithm')->defaultValue('sha1')->end()
                        ->booleanNode('encodeHashAsBase64')->defaultTrue()->end()
                    ->end()
                ->end()
             ->end();
    }

    /**
     * Returns the id of listener.
     *
     * @return string
     */
    protected function getListenerId()
    {
        return 'amf_webservices_security.security.authentication.listener';
    }
    
    /**
     * Creates the listener.
     *
     * @return string
     */
    protected function createListener($container, $id, $config, $userProvider)
    {
        $listenerId = $this->getListenerId();
        
        $listener = new DefinitionDecorator($listenerId);
        $listener->replaceArgument(2, $id);

        $listenerId .= '.'.$id;
        $container->setDefinition($listenerId, $listener);
        
        return $listenerId;
    }

    /**
     * Creates a provider of authentication.
     *
     * @return string
     */
    protected function createAuthProvider(ContainerBuilder $container, $id, $config, $userProviderId)
    {
        $encoderId = 'amf_webservices_security.security.encoder.'.$id;
        $container->setDefinition($encoderId, new DefinitionDecorator('amf_webservices_security.security.encoder'));
        
        if (isset($config['encoder']['algorithm'])) {
            $container->getDefinition($encoderId)->replaceArgument(0, $config['encoder']['algorithm']);
        }

        if (isset($config['encoder']['encodeHashAsBase64'])) {
            $container->getDefinition($encoderId)->replaceArgument(1, $config['encoder']['encodeHashAsBase64']);
        }
        
        $provider = 'amf_webservices_security.security.authentication.provider.'.$id;
        
        $container
            ->setDefinition($provider, new DefinitionDecorator('amf_webservices_security.security.authentication.provider'))
            ->replaceArgument(0, new Reference($encoderId))
            ->replaceArgument(2, new Reference($userProviderId))
            ->replaceArgument(3, $id)
            ->replaceArgument(4, $config['lifetime']);

        return $provider;
    }
    
    /**
     * Disables remember me functionality.
     *
     * @param array $config The configuration of security.
     *
     * @return boolean
     */
    protected function isRememberMeAware($config)
    {
        return false;
    }
}
