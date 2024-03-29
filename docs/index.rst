Quick view
==========

Introduction
------------

**aduneoclientfedid** is used to test OpenID Connect, OAuth 2 and SAML configurations. It acts as a federation client mimicking an application.

After an initial configuration, various flows are tested. The application may obtain tokens and assertions that can be validated, then used for user info, introspection and exchange.

It is useful for:

* Testing a newly installed identity provider
* Learning how identity federation works
* Understanding a specific feature
* Debugging a faulty client configuration by replicating it
* Learning how to code OpenID Connect, OAuth 2 or SAML 2

Contents
--------

.. toctree::

   Quick View <self>
   protocols
   installation
   running
   runningFromSources
   testingOpenIDConnect
   testingOAuth2
   testingSAML2
   generalconf