Testing OpenID Connect
======================

**aduneoclientfedid** acts as an OpenID Connect Relaying Party (RP). It triggers user authentications, receives ID Tokens and retrieves user information through the userinfo endpoint.

Once an ID token is obtained, if the RP is compatible, the token can be exchanged for an access token (using OAuth 2.0 Token Exchange - RFC 8693). This simulates a web application that authenticates users (OpenID Connect) and then connects to web services (OAuth 2).

How it works
------------

You will need:

* Aduneoclientfedid installed and started, usually on the local machine
* Access to the OpenID Provider (the identity server you want to test)
* A test user created on the OpenID Provider (along with its password or any other authentication method)
* Both aduneoclientfedid and the OP configured (more on that later)

When all of this is done, connect with a web browser to aduneoclientfedid main page. Usually https://localhost 

.. note::
    
    it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes.

The browser will probably display a warning since loading a page from localhost is restricted when the connection is encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you have configured a flow with an OpenID Provider (as explained in the next part), you can click on the Login button next to the name of the configuration you wish to test.

A page is displayed with the parameters and options from the configuration. You have the liberty to change whatever you need to perform your test. The changes only apply to the current session and leave configuration data as they are.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the IdP where authentication occurs. Then the browser is redirected back to *aduneoclientfedid* with the result (success or error).

A page is displayed with the ID Token and its validation parameters (if authentification was successful).

You can then start a userinfo flow to retrieve information in the ID token.

The userinfo request is added to the page and one again you change any value before hitting *Send request*.

You can also restart an authentification flow, with the exact same parameters as the first one.

Configuration
-------------

A configuration represents a flow between an OP and a client. Once a configuration is defined, authentications can be started.

You can define as many configurations as you want, with different OPs or with the same OP.

A new configuration is created with the *Add OIDC Client* button. A name is required. Choose any name that speaks to you, for it has no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

Some parameters of the OIDC flow are configured in the OP and other in *aduneoclientfedid*.

OpenID Provider configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The OP needs the minimum following information:

* redirect URI: the *aduneoclientfedid* URL where the browser is directed after the user has been authenticated

This information is taken from the *Redirect URI* field on the *aduneoclientfedid* configuration page. The default URL is https://localhost/client/oidc/login/callback (varies depending on configuration specifics). You can change it to suit your need. 
Make sure any custom URL is not used in a configuration from a different protocol (OAuth 2 or SAML). To avoid that, it is better to add an indication about the protocol (oidc) in the URL.

.. Warning::

    Beware that you must enter the same URL in the configurations of the OP and *aduneoclientfedid*.

Some OP software automatically generate a client ID and a client secret. You need this information to configure *aduneoclientfedid*. Other software require this information is manually entered.

Depending on the OP, additional configuration is required, for example the definition of the allowed scopes, or the authentication methods allowed for the various endpoints.

aduneoclientfedid configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

*aduneoclientfedid* needs the following information:

* The OP endpoints: the URL where the browser is directed to authenticate the user and URLs for various OP web services (token retrieval, public keys, userinfo, etc.)
* Client ID, identifying the client in the OP
* Client secret (the password associated with the client ID)
* The method used to authenticate the client
  
While it is possible to detail every endpoint URL, the easiest way is to give the discovery URI, also known as the well known configuration endpoint that returns the *configuration document* with all necessary information.

This discovery URL is the following construct: issuer URL + */.well-known/openid-configuration*.

Here are some examples:

* Azure AD: https://login.microsoftonline.com/\/v2.0/.well-known/openid-configuration
* Okta: https://<domain>.okta.com/.well-known/openid-configuration
* ForgeRock AM: https://<server>/am/oauth2/<realm>/.well-known/openid-configuration
* Keycloak: https://<server>/realms/<realm>/.well-known/openid-configuration
  
The client ID and client secret are either generated by the OP or entered in the OP configuration.

The authentication method describes how these credentials are transmitted:

* POST: in the HTTP body (widely used)
* Basic: in the HTTP headers
  
Some OPs accept any authentication method while other must be precisely configured.

Default parameters
^^^^^^^^^^^^^^^^^^

When configuring an OpenID Connect service, you also provide default values for flow parameters.

The *scopes* are keywords representing information that the OP should send alongside the identity after a successfull authentication. Multiple scopes are separated by spaces.

The parameter MUST contain *openid* per OIDC’s flow configured in the client (it distinguishes an OpenID Connect flow and an OAuth 2 flow).

The OpenID Connect Specifications define several default scopes and additional ones which can be configured in the OP.

The most used scopes for testing purposes are "openid email profile" :

* openid indicates an OpenID Connect flow
* email is obviously the email address
* profile returns basing information about the user: name, given name, gender, locale, birthdate, etc.
  
aduneoclientfedid is only compatible with the code response type, the implicit flow being deprecated since 2018.

Options
^^^^^^^

Options describe aduneoclientfedid's behavior out of the OpenID Connect specifications.

The only option indicates is HTTPS certificates must be validated.

When testing a production environment, it is advised to verify certificates, to replicate the exact flows.

Other environments typically have specific certificates (self-signed or signed by an internal PKI). Since certificate verification will likely fail, it's best to disable it.

OpenID Connect Logout
---------------------

*aduneoclientfedid* implements *OpenID Connect RP-Initiated Logout 1.0*, but not yet either Front-Channel or Back-Channel.

Logout is initiated from the home page.