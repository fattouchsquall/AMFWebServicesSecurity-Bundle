Getting started with AMFWebServiceClientBundle
=======================================

1) Installation
----------------------------------


The first step is to tell composer that you want to download AMFWebServiceClientBundle which can
be achieved by entering the following line at the command prompt:

```bash
    $ php composer.phar require amf/webservices-security-bundle: ~1.0
```

> ***Note*** This command requires you to have Composer installed globally, as explained
in the [installation chapter](https://getcomposer.org/doc/00-intro.md)
of the Composer documentation.

After the download of the files is achieved, register the bundle in `app/AppKernel.php`:

```php
# app/AppKernel.php

public function registerBundles()
{
    return array(
        // ...
        new AMF\WebServicesClientBundle\AMFWebServicesClientBundle(),
    );
}
```