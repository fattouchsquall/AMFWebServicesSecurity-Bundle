<?php

namespace Nordnet\WebServicesSecurityBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;

use Symfony\Component\DependencyInjection\ContainerBuilder;

use AMF\WebServicesSecurityBundle\DependencyInjection\Security\Factory\WsseFactory;

class AMFWebServicesSecurityBundle extends Bundle
{
    /**
     * Builds the bundle.
     *
     * This is used to register the security listener to support Symfony 2.1.
     *
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new WsseFactory());
    }
}
