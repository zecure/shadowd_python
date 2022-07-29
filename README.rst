.. image:: https://shadowd.zecure.org/img/logo_small.png
.. image:: https://github.com/zecure/shadowd_python/actions/workflows/analyze.yml/badge.svg
    :target: https://github.com/zecure/shadowd_python/actions/workflows/analyze.yml
.. image:: https://sonarcloud.io/api/project_badges/measure?project=zecure_shadowd_python&metric=alert_status
    :target: https://sonarcloud.io/dashboard?id=zecure_shadowd_python

**Shadow Daemon** is a collection of tools to **detect**, **record** and **prevent** **attacks** on *web applications*.
Technically speaking, Shadow Daemon is a **web application firewall** that intercepts requests and filters out malicious parameters.
It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability.

This component can be used to connect Python applications with the `background server <https://github.com/zecure/shadowd>`_.

Documentation
=============
For the full documentation please refer to `shadowd.zecure.org <https://shadowd.zecure.org/>`_.

Installation
============
You can install the package with easy_install or pip:

::

   easy_install shadowd
   pip install shadowd

It is also possible to clone this repository and install the package manually:

::

    python setup.py install

You also have to create a configuration file. You can copy *misc/examples/connectors.ini* to */etc/shadowd/connectors.ini*.
The example configuration is annotated and should be self-explanatory.

CGI
---
To protect CGI applications you simply have to load the module:

::

    import shadowd.cgi_connector

Django
------
Django applications require a small modification. It is necessary to create a hook to intercept requests.
To do this create the file *middleware/shadowdconnector.py* in the application directory:

::

    from shadowd.django_connector import InputDjango, OutputDjango, Connector

    def shadowdconnector(get_response):
        def middleware(request):
            input = InputDjango(request)
            output = OutputDjango()

            status = Connector().start(input, output)
            if not status == True:
                return status

            return get_response(request)

        return middleware


There also has to be an empty *__init__.py* file in the middleware directory.
Next you have to register the middleware in the *settings.py* file of your application:

::

    MIDDLEWARE_CLASSES = (
        'middleware.shadowdconnector.shadowdconnector',
        # ...
    )

The connector should be at the beginning of the *MIDDLEWARE_CLASSES* list.

Flask
------
Flask applications require a small modification as well. It is necessary to create a hook to intercept requests:

::

    from shadowd.flask_connector import InputFlask, OutputFlask, Connector

    @app.before_request
    def before_req():
        input = InputFlask(request)
        output = OutputFlask()

        Connector().start(input, output)
