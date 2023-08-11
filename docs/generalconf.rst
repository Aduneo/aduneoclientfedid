General configuration
=====================

Some configuration parameters affecting the server behaviour are modified in the configuration file, using your favorite editor. There is no web console now for these parameters.

The configuration file is named clientfedid.cnf and is in the conf directory that has been created in the current folder (the one from which the python command has been issued).

It's a JSON file, so be careful of trailing commas. As a reminder, the following syntax is not permitted by JSON:

.. code-block:: console

    {
    "param1": "value1",
    "param2": "this will result in an error",
    }

.. tip::
    Remove the last comma to make it JSON compliant

There are 6 main sections in the configuration file:

* Meta: information about the configuration file itself. It only contains the name of the file containing the key used to encrypt passwords
* Server: HTTP server parameters (port, SSL, etc.)
* Preferences
* oidc_clients, oauth_clients, saml_clients: these parts detail the various clients and configurations in the application
  
Any manual change in thre configuration file requires the server to be restarted (Ctrl-C then clientfedid/aduneoclientfedid/python -m aduneoclientfedid).

meta/key: encryption key file name
----------------------------------

All parameters with a name ending with an exclamation point (!) are automatically encrypted (client secrets), using a symmetric key.

A key is automatically generated at first launch and store in a file named clientfedid.key.

It is a good practice to protect this file.

server/host
-----------

Identifies the network card used by the HTTP server.

Using the default localhost makes sure no other machine is (easily...) able to access it.

An empty value ("") opens it to anyone (depending on your local firewall settings).

It can be a name or an IP address.

server/port
-----------

Listening port for the HTTP server.

Default is 443. It might not work on Unix/Linux systems. The easiest fix is to choose a port number greater than 1024 (8443 is a good candidate).

server/ssl
----------

Activates HTTPS. Possible values are *on* and *off*.

Since most of the security of OpenID Connect/OAuth 2 relies on HTTPS, it is advisable to leave the default (*on*).

But you may have to turn it off for testing purposes.

server/ssl_key_file and server/ssl_cert_file
--------------------------------------------

When SSL is activated, these parameters contains the file with:

* The SSL private key (*ssl_key_file*), PEM format
* The associated certificate (*ssl_cert_file*), PEM format
  
If those files are not referenced in the configuration file (which is the default), aduneoclientfedid will automatically create a key and certificate. Those items are deleted after the server is stopped.

The certificate is self-signed, with server/host as the subject (the FQDN of the machine if server/host is empty).

preferences/logging/handler
---------------------------

List of logging handlers:

* Console: displays logs in the window used to launch the server
* File: adds logs in a file in a directory (*logs*) created alongside *conf* directory.
* Webconsole: displays logs in a browser window that can be opened by "console" button on the upper right side of the page, or automatically when an authentication flow is started

By default, all handlers are activated.

preferences/open_webconsole
---------------------------

*on* if the browser window displaying logs is automatically opened every time an authentication flow is started (default).

preferences/clipboard/encrypt_clipboard
---------------------------------------

The clipboard stores all texts typed in application forms, to be easily used multiple times without having to enter them each time.

Its content is stored in the conf directory.

If *encrypt_clipboard* is on, the file is encrypted using *clientfedid.key* as a key. This is the default.

Otherwise, its content is in plain text.

preferences/clipboard/remember_secrets
--------------------------------------

Indicates if secrets are stored in the clipboard (default is *off*).