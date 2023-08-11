Testing OAuth 2
===============

*aduneoclientfedid* acts both as a OAuth 2 client (a web app) and a resource server (RS, ie a web service).

In a first step *aduneoclientfedid* simulates a client, triggers a user authentication and receives an access token (AT). Then it takes the role of a resource server that would have been inkoved by the client. The RS would have received the access token and now has to validate it.

The validation method depends on the nature of the access token:

* JWTs are validated by verifying the signature (not yet implemented by *aduneoclientfedid* for ATs)
* Opaque tokens must be introspected (presented to the introspection endpoint for validation and user information retrieval)
  
*aduneoclientfedid* performs token exchanges (RFC 8693) to get other access tokens or ID tokens from an access token. At the time of writing very few AS have implemented this RFC.

OAuth 2 flows (introspections and token exchanges) can also be initiated after a SAML authentication.

How it works
------------

You will need:

* *aduneoclientfedid* installed and started, usually on the local machine
* Access to the Authorization Server (the identity server you want to test)
* A test user created on the Authorization server (along with its password or any other authentication method)
* Both *aduneoclientfedid* and the OP configured (more on that later)

When all of this is done, connect with a web browser to *aduneoclientfedid* main page. Usually https://localhost 

.. note::
    
    it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes.

The browser will probably display a warning since loading a page from *localhost* is restricted when the connection is encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you have configured a flow with an *authorization* server (as explained in the next part), you can click on the *Login* button next to the name of the configuration you wish to test.

A page is displayed with the parameters and options from the configuration. You have the liberty to change whatever you need to perform your test. The changes only apply to the current session and leave configuration data as they are.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the AS where authentication occurs. Then the browser is redirected back to *aduneoclientfedid* with the result (success or error).

A page is displayed with the Access Token.

Then, you can start an introspection flow or a token exchange flow.

Configuration
-------------

A configuration represents a flow between an Authorization Server and a client. Once a configuration is defined, authorizations can be started.

You can define as many configurations as you want, with different ASs or with the same AS.

A new configuration is created with the *Add OAuth Client* button. A name is required. Choose any name that speaks to you, for it has no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

Some parameters of the OAuth 2 flow are configured in the OP and other in *aduneoclientfedid*.

Authorization Server configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The AS needs the minimum following information:

* redirect URI: the *aduneoclientfedid* URL where the browser is directed after the user has been authenticated
  
This information is taken from the *Redirect URI* field on the *aduneoclientfedid* configuration page. The default URL is https://localhost/client/oidc/login/callback (varies depending on configuration specifics). You can change it to suit you need. Make sure any custom URL is not used in a configuration from a different protocol (OIDC or SAML). To avoid that, it is better to add an indication about the protocol (oidc) in the URL.
Beware that you must enter the same URL in the configurations of the OP and *aduneoclientfedid*.

Some AS software automatically generate a client ID and a client secret. You need this information to configure *aduneoclientfedid*. Other software require this information is manually entered.

Depending on the AS, additional configuration is required, for example the definition of the allowed scopes, or the authentication methods allowed for the various endpoints.

If introspection is used for validating the AT, you need to create a configuration for aduneoclientfedid acting as a resource server. All is needed is a login and a secret. Each authorization server software has its own configuration way:

* Some have dedicated objects to represent a RS
* Others treat RS as clients with minimal configuration Refer to the software documentation to determine how to proceed.
  
aduneoclientfedid configuration
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The *aduneoclientfedid* configuration page is split in 2 sections:

* *"Token request by the client"* is the configuration when it acts as a client
* *"Token validation by the API (resource server)"* when it acts as a resource server
  
To obtain an Access Token, the following information is needed:

* The AS endpoints: URL where the browser is directed to authenticate the user and URLs for various AS web services (token retrieval, introspection, etc.)
* Client ID, identifying the client in the AS
* Client secret (the password associated with the client ID)
* The method used to authenticate the client

OAuth does not have a discovery URI mechanism like OpenID Connect, where the client can retrieve all endpoints (and additional parameters). Normally, each individual endpoint must be provided.

But some AS software publish a discovery URI, which can be the same as OpenID Connect, or different. If it's different, make sure to enter the correct URI. Otherwise you might have an unpredictable behavior.

This is the case with Okta :

* https://<domain>.okta.com/.well-known/oauth-authorization-server

ForgeRock AM has the same discovery URI for OpenID Connect and OAuth 2.

The client ID and client secret are either generated by the AS or entered in the AS configuration.

The authentication method describes how these credentials are transmitted:

* POST: in the HTTP body (widely used)
* Basic: in the HTTP headers
  
Some Authorization Servers accept any authentication method while other must be precisely configured.

If tokens are validated by introspection, you can configure how to perform it:

* Introspection endpoint (if not retrieved through the discovery URI)
* Resource server client ID: the login used by the web service that has received the Access Token
* Resource server secret: the corresponding secret (aduneoclientfedid is only compatible with a password at the moment)

Default parameters
^^^^^^^^^^^^^^^^^^

When configuring an OAuth 2 service, you also provide default values for flow parameters.

The *scopes* are keywords representing the type of access that is requested. They are entirely dependent on your own installation. They usually represent access types (read, write, create, delete, etc.).

The *resource* parameter is defined by RFC 8707 but not implemented by many AS. Check compatibility before using it.

*aduneoclientfedid* is only compatible with the code response type, the implicit flow being deprecated since 2018.

Options
^^^^^^^

Options describe aduneoclientfedid's behavior outside of the OAuth RFCs.

The only option indicates if HTTPS certificates must be validated.

When testing a production environment, it is advised to verify certificates, to replicate the exact flows.

Other environments typically have specific certificates (self-signed or signed by an internal PKI). Since certificate verification will likely fail, it's best to disable it.

Access Token Introspection
--------------------------

After an access token has been obtained, it can be introspected.

After clicking on the "Introspect AT" button, a form is displayed in two parts:

* First the parameters defined by RFC 7662 (token and token type hint)
* Then the request as it is going to be sent to the authorization server: endpoint, data, authentication parameters
  
Any change in the first part is reflected on the second (but not the other war around).

During tests, you'll probably have to enter the same information many times (credentials for instance). To help you with that, you can use the internal clipboard. It keeps all inputs that are entered so that you just have to select it when it's needed again. The clipboard is opened when clicking the icon on the right of each form field. By default, passwords are not stored in the clipboard, but a configuration parameter enables this feature.

Refreshing Access Tokens
------------------------

If a refresh token (RT) was retrieved during OAuth flow, it can be used to get a new access token.

As with introspection, a two-part form is displayed:

* Top form: parameters defined by RFC 6749 (section 6)
* Bottom form: the request as it will be sent to the authorization server
  
Token Exchange
--------------

RFC 8693 defines a way to obtain a new token (ID or access) from an existing valid token (ID or access).

Few authorization servers have implemented it, so check it's available.