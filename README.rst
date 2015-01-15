**Shadow Daemon** is a collection of tools to **detect**, **protocol** and **prevent** **attacks** on *web applications*. Technically speaking, Shadow Daemon is a **web application firewall** that intercepts requests and filters out malicious parameters. It is a modular system that separates web application, analysis and interface to increase security, flexibility and expandability.

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

You also have to create a configuration file. You can copy *misc/examples/connectors.ini* to */etc/shadowd/connectors.ini*. The example configuration is annotated and should be self-explanatory.

CGI
---
To protect CGI applications you simply have to load the module:

::

    import shadowd.cgi_connector
