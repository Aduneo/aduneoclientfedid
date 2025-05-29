# aduneoclientfedid
Identity Federation Test Client by Aduneo

## Quick view

**aduneoclientfedid** is used to test OpenID Connect, OAuth 2 and SAML configurations. It acts as a federation client mimicking an application.

After an initial configuration, various flows are tested. The application may obtain tokens and assertions that can be validated, then used for user info, introspection and exchange.

It is useful for:
- testing a newly installed identity provider
- learning how identity federation works
- understanding a specific feature
- debugging a faulty client configuration by replicating it
- learning how to code OpenID Connect, OAuth 2 or SAML 2


## Supported protocols

**aduneoclientfedid** supports OpenID Connect, OAuth 2 and SAML.

### OpenID Connect

The client is compatible with OpenID Connect Core 1.0 incorporating errata set 1 (https://openid.net/specs/openid-connect-core-1_0.html).

### OAuth 2

The client is compatible with
- RFC 6749 The OAuth 2.0 Authorization Framework (https://www.rfc-editor.org/rfc/rfc6749)
- RFC 7662 OAuth 2.0 Token Introspection (https://www.rfc-editor.org/rfc/rfc7662)
- RFC 8707 Resource Indicators for OAuth 2.0 (https://www.rfc-editor.org/rfc/rfc8707)
- RFC 8693 OAuth 2.0 Token Exchange (https://www.rfc-editor.org/rfc/rfc8693)

### SAML

The client is compatible with the essential parts of SAML V2.0 Specifications (http://saml.xml.org/saml-specifications)

and its use with OAuth 2 :
- RFC 7522 Security Assertion Markup Language (SAML) 2.0 Profile
      for OAuth 2.0 Client Authentication and Authorization Grants (https://www.rfc-editor.org/rfc/rfc7522)


## Quick install on Windows

Not everyone is a Python expert.

If you don't have Python installed on your Windows computer, follow this procedure to quicky run ClientFedID without the need of local administrator rights:
- create a folder for ClientFedID
- download the latest WinPython distribution from https://winpython.github.io/#releases
  (you only need the dot version, for exemple Winpython64-3.12.8.0dot.7z)
- unzip the file in the folder ; it will create a subfolder with a name starting with WPy64
- run WinPython Command Prompt.exe in this subfolder
  (a new Windows Command window will appear)
- type 
```console
> pip install aduneoclientfedid
```
- start the app with
```console
> aduneoclientfedid
```
- open your favorite browser and go to https://localhost
- a warning page will be displayed with a certificate error, which is expected
- click on *advanced* and then on *Proceed to localhost (unsafe)* or on *Accept the risk and continue* depending on your browser
- and voilà !

Attention: this version does not have SAML support. Installing SAML capabilies might prove tricky, because of the *xmlsec* library. 
It is not compatible with all Python versions on Windows.

You can install ClientFedID with SAML:
```console
> pip install aduneoclientfedid[saml]
```


## Normal installation (Windows and Linux)

**aduneoclientfedid** is a web server that is installed locally, most of the time on *localhost* and accessed with a web browser.

Python must be installed on the system which will run the web server.
It is compatible with Python 3.6 and later.

It has been tested on Windows and various Linux systems. On Windows, it can be executed from a command line prompt
or in a Powershell window.

The simpliest way to install it is to download it from PyPI.

First, it is advisable to create a virtual environment in a directory where you want to install the software.
```console
$ mkdir clientfedid
$ cd clientfedid
$ python -m venv my-env
```
(depending on your operating system, you might have to use *python3* instead of *python*, or use a different command - *virtualenv -p python3 my-env* for instance)

and activate it. Depending on the system:
```console
$ source my-env/bin/activate
```
or
```console
> my-env\Script\activate
```
then install it with *pip*:
```console
$ pip install aduneoclientfedid
```
By default, packages needed for SAML are not installed, because they are tricky on some systems. If you want to use SAML,
install with the [saml] option:
```console
$ pip install aduneoclientfedid[saml]
```

You may have to manually install some Linux packages. Please refer to the xmlsec documentation (https://pypi.org/project/xmlsec)
for more information.

If SAML is not working, the console displays
```console
SAML disabled because xmlsec is not installed
```

You may have to reinstall xmlsec without binaries:
```console
pip install --force-reinstall --no-binary lxml,xmlsec lxml xmlsec
```


## Running aduneoclientfedid

Once the packages are successfully installed, create a root directory where the configuration and logs will be created. 
This root directory can be located anywhere on the disk. The natural option is the directory where the Python
virtual environment (*venv*) has been created.

If you want to create a new root directory:
```console
mkdir clientfedid
cd clientfedid
```

Two directories will be created in this directory:
- *conf* where a default configuration file is generated
- *log*

Make sure the current user is allowed to create these items.

There are several ways of launching the server:
```console
clientfedid
aduneoclientfedid
python -m aduneoclientfedid
```
If successfull, a similar line is displayed:
```console
Fri Jan 6 18:15:52 2023 Server UP - https://localhost:443
```

On Unix/Linux systems, non-administrative users are prevented by default to start a server on ports below 1024.

HTTPS running on port 443, the server won't launch, with the following error:
```console
PermissionError: [Errno 13] Permission denied
```

The easiest way out is to modify the port to a value larger than 1024, for instance 8443.

To change the port, just had the *-port <port>* argument. Launching the server on port 8443 becomes:
```console
clientfedid -port 8443
```

When you use the previous command to launch the client for the first time (when the *conf* directory has not yet been created), the port is configured in the configuration file (the file *clientfedid.cnf* in the *conf* directory).
Now you don't have to specify the port in the command line for the next execution.

You can also change the listening interface, with the *-host <host>* argument.

By default, the server only listens on the *localhost* interface (127.0.0.1), meaning you can only reach it from the same computer
(with a web browser on https://localhost).
If you want to access it from another computer, you have to change the listening network interface.

To listen on any interface, run the server with an empty host:
```console
clientfedid -host ""
```
Now you can point a browser to something like https://mycomputer.domain.com.

Once the server is running, stop it with Ctrl+C.

This server is only meant to be running for the time when the tests are conducted. It is not optimized to run for a long time.
It is not optimized to run as a demon. It is definitely not secure enough.

It is usually run on the tester's computer or on a computer controlled by the tester.


## Running from a container

A container image is published on Docker Hub : **aduneo/aduneoclientfedid**.

To retrieve it
```console
docker pull aduneo/aduneoclientfedid
```
To run it, just map the HTTPS (443) port of the container:
```console
docker run -p 443:443 -it aduneo/aduneoclientfedid
```
ClientFedID is then available on https://localhost.

Should you prefer a different port, for example 8443:
```console
docker run -p 8443:443 -it aduneo/aduneoclientfedid
```
As is usual with containers, a restart loses the configuration.

You might want to persist it on the host. Just map the **/opt/conf** directory.

On Windows, create a *conf-for-container* (or any other name) directory and run:
```console
docker run -p 443:443 -v .\conf-for-container:/opt/conf -it aduneo/aduneoclientfedid
```
The *docker-compose.yml* file in the repository does just that. From the location of the file:
```console
docker-compose up
```


## Running from sources

There are situations where it is not possible to install the server with pip.

It's still possible to run it from the sources.

First, the following packages must be manually installed:
- certifi
- charset_normalizer (at the time of writing, urllib3 is only compatible with version 2, not the newer version 3)
- idna
- urllib3
- requests
- cffi
- pycparser
- cryptography
- pyopenssl
- deprecated
- wrapt
- jwcrypto

Additionaly (for SAML):
- lxml
- xmlsec

Sources are downloaded from https://github.com/Aduneo/aduneoclientfedid, usually as a ZIP download through the *Code* button.

Create a root directory.

Create a Python virtual environment, activate it and install all necessary packages, in the order given earlier.

Unzip the sources, go to the directory containing the aduneoclientfedid folder and run:
```console
python -m aduneoclientfedid
```


## Testing OpenID Connect

**aduneoclientfedid** acts as an OpenID Connect Relaying Party (RP). It triggers user authentications, receives ID Tokens and retrieves
user information through the *userinfo* endpoint.

Once an ID token is obtained, if the RP is compatible, the token can be exchanged for an access token
(using OAuth 2.0 Token Exchange - RFC 8693).
This simulates a web application that authenticates users (OpenID Connect) and then connects to web services (OAuth 2).

### How it works

You will need
- *aduneoclientfedid* installed and started, usually on the local machine
- access to the OpenID Provider (the identity server you want to test)
- a test user created on the OpenID Provider (along with its password or any other authentication method)
- both *aduneoclientfedid* and the OP configured (more on that later)

When all of this is done, connect with a web browser to *aduneoclientfedid* main page. Usually https://localhost
(it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes).

The browser will probably display a warning since loading a page from *localhost* is restricted when the connection is
encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you have configured a flow with an *OpenID Provider* (as explained in the next part), you can click on the *Login* button next to the name of the configuration you wish to test.

A page is displayed with the parameters and options from the configuration. You have the liberty to change whatever you need to
perform your test. The changes only apply to the current session and leave configuration data as they are.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the IdP where authentication occurs. Then the browser is redirected back to *aduneoclientfedid*
with the result (success or error).

A page is displayed with the ID Token and its validation parameters (if authentification was successful).

You can then start a userinfo flow to retrieve information in the ID token.

The userinfo request is added to the page and one again you change any value before hitting *Send request*.

You can also restart an authentification flow, with the exact same parameters as the first one.


### Configuration

A configuration represents a flow between an OP and a client. Once a configuration is defined, authentications can be started.

You can define as many configurations as you want, with different OPs or with the same OP.

A new configuration is created with the *Add OIDC Client* button. A name is required. Choose any name that speaks to you, for it has
no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

Some parameters of the OIDC flow are configured in the OP and other in *aduneoclientfedid*.

#### OpenID Provider configuration

The OP needs the minimum following information:
- redirect URI: the *aduneoclientfedid* URL where the browser is directed after the user has been authenticated

This information is taken from the *Redirect URI* field on the *aduneoclientfedid* configuration page. The default URL is https://localhost/client/oidc/login/callback 
(varies depending on configuration specifics). You can change it to suit you need. Make sure any custom URL is not used in a configuration from a different protocol
(OAuth 2 or SAML). To avoid that, it is better to add an indication about the protocol (oidc) in the URL.  
Beware that you must enter the same URL in the configurations of the OP and *aduneoclientfedid*.

Some OP software automatically generate a client ID and a client secret. You need this information to configure *aduneoclientfedid*.
Other software require this information is manually entered.

Depending on the OP, additional configuration is required, for example the definition of the allowed scopes, or the authentication methods allowed for the various endpoints.

#### aduneoclientfedid configuration

*aduneoclientfedid* needs the following information:
- the OP endpoints: the URL where the browser is directed to authenticate the user and URLs for various OP web services (token retrieval, public keys, userinfo, etc.)
- client ID, identifying the client in the OP
- client secret (the password associated with the client ID)
- the method used to authenticate the client

While it is possible to detail every endpoint URL, the easiest way is to give the discovery URI, also known as the well known
configuration endpoint that returns the *configuration document* with all necessary information.

This discovery URL is the following construct: issuer URL + */.well-known/openid-configuration*.

Here are some examples:
- Azure AD: https://login.microsoftonline.com/\<IdP UID>/v2.0/.well-known/openid-configuration
- Okta: https://\<domain>.okta.com/.well-known/openid-configuration
- ForgeRock AM: https://\<server>/am/oauth2/\<realm>/.well-known/openid-configuration
- Keycloak: https://\<server>/realms/\<realm>/.well-known/openid-configuration

The client ID and client secret are either generated by the OP or entered in the OP configuration.

The authentication method describes how these credentials are transmitted:
- POST: in the HTTP body (widely used)
- Basic: in the HTTP headers

Some OPs accept any authentication method while other must be precisely configured.

#### Default parameters

When configuring an OpenID Connect service, you also provide default values for flow parameters.

The *scopes* are keywords representing information that the OP should send alongside the identity after a successfull
authentication. Multiple scopes are separated by spaces.

The parameter MUST contain *openid* per OIDC’s flow configured in the client (it distinguishes an OpenID Connect flow and an OAuth 2 flow).

The OpenID Connect Specifications define several default scopes and additional ones which can be configured in the OP.

The most used scopes for testing purposes are "openid email profile" :
- openid indicates an OpenID Connect flow
- email is obviously the email address
- profile returns basing information about the user: name, given name, gender, locale, birthdate, etc.

*aduneoclientfedid* is only compatible with the *code* response type, the implicit flow being deprecated since 2018.

#### Options

Options describe *aduneoclientfedid*'s behavior out of the OpenID Connect specifications.

The only option indicates is HTTPS certificates must be validated.

When testing a production environment, it is advised to verify certificates, to replicate the exact flows.

Other environments typically have specific certificates (self-signed or signed by an internal PKI). Since certificate verification will likely fail, it's best to disable it.


### OpenID Connect Logout

*aduneoclientfedid* implements *OpenID Connect RP-Initiated Logout 1.0*, but not yet either Front-Channel or Back-Channel.

Logout is initiated from the home page.


## Testing OAuth 2

*aduneoclientfedid* acts both as a OAuth 2 client (a web app) and a resource server (RS, ie a web service).

In a first step *aduneoclientfedid* simulates a client, triggers a user authentication and receives an access token (AT).
Then it takes the role of a resource server that would have been inkoved by the client. The RS would have received the access token and now has to validate it.

The validation method depends on the nature of the access token:
- JWTs are validated by verifying the signature (not yet implemented by *aduneoclientfedid* for ATs)
- opaque tokens must be *introspected* (presented to the introspection endpoint for validation and user information retrieval)

*aduneoclientfedid* performs token exchanges (RFC 8693) to get other access tokens or ID tokens from an access token. At the time of writing very few AS have implemented this RFC.

OAuth 2 flows (introspections and token exchanges) can also be initiated after a SAML authentication.

### How it works

You will need
- *aduneoclientfedid* installed and started, usually on the local machine
- access to the Authorization Server (the identity server you want to test)
- a test user created on the Authorization server (along with its password or any other authentication method)
- both *aduneoclientfedid* and the OP configured (more on that later)

When all of this is done, connect with a web browser to *aduneoclientfedid* main page. Usually https://localhost
(it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes).

The browser will probably display a warning since loading a page from *localhost* is restricted when the connection is
encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you have configured a flow with an *authorization server* (as explained in the next part), you can click on the *Login* button next to the name of the configuration you wish to test.

A page is displayed with the parameters and options from the configuration. You have the liberty to change whatever you need to
perform your test. The changes only apply to the current session and leave configuration data as they are.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the AS where authentication occurs. Then the browser is redirected back to *aduneoclientfedid*
with the result (success or error).

A page is displayed with the Access Token.

Then, you can start an introspection flow or a token exchange flow.

### Configuration

A configuration represents a flow between an Authorization Server and a client. Once a configuration is defined, authorizations can be started.

You can define as many configurations as you want, with different ASs or with the same AS.

A new configuration is created with the *Add OAuth Client* button. A name is required. Choose any name that speaks to you, for it has
no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

Some parameters of the OAuth 2 flow are configured in the OP and other in aduneoclientfedid.

#### Authorization Server configuration

The AS needs the minimum following information:
- redirect URI: the *aduneoclientfedid* URL where the browser is directed after the user has been authenticated

This information is taken from the *Redirect URI* field on the *aduneoclientfedid* configuration page. The default URL is https://localhost/client/oidc/login/callback 
(varies depending on configuration specifics). You can change it to suit you need. Make sure any custom URL is not used in a configuration from a different protocol
(OIDC or SAML). To avoid that, it is better to add an indication about the protocol (oidc) in the URL.  
Beware that you must enter the same URL in the configurations of the OP and *aduneoclientfedid*.

Some AS software automatically generate a client ID and a client secret. You need this information to configure *aduneoclientfedid*. Other software require this information is manually entered.

Depending on the AS, additional configuration is required, for example the definition of the allowed scopes, or the authentication methods allowed for the various endpoints.

If introspection is used for validating the AT, you need to create a configuration for *aduneoclientfedid* acting as a resource server. All is needed is a login and a secret.
Each authorization server software has its own configuration way
- some have dedicated objects to represent a RS
- others treat RS as clients with minimal configuration
Refer to the software documentation to determine how to proceed.

#### aduneoclientfedid configuration

The *aduneoclientfedid* configuration page is split in 2 sections:
- "Token request by the client" is the configuration when it acts as a client
- "Token validation by the API (resource server)" when it acts as a resource server

To obtain an Access Token, the following information is needed:
- the AS endpoints: URL where the browser is directed to authenticate the user and URLs for various AS web services (token retrieval, introspection, etc.)
- client ID, identifying the client in the AS
- client secret (the password associated with the client ID)
- the method used to authenticate the client

OAuth does not have a discovery URI mechanism like OpenID Connect, where the client can retrieve all endpoints (and additional parameters).
Normally, each individual endpoint must be provided.

But some AS software publish a discovery URI, which can be the same as OpenID Connect, or different. If it's different, make sure to enter the correct URI. Otherwise 
you might have an unpredictable behavior.

This is the case with Okta :
- https://\<domain>.okta.com/.well-known/oauth-authorization-server

ForgeRock AM has the same discovery URI for OpenID Connect and OAuth 2.

The client ID and client secret are either generated by the AS or entered in the AS configuration.

The authentication method describes how these credentials are transmitted:
- POST: in the HTTP body (widely used)
- Basic: in the HTTP headers

Some Authorization Servers accept any authentication method while other must be precisely configured.

If tokens are validated by introspection, you can configure how to perform it:
- introspection endpoint (if not retrieved through the discovery URI)
- resource server client ID: the login used by the web service that has received the Access Token
- resource server secret: the corresponding secret (*aduneoclientfedid* is only compatible with a password at the moment)

#### Default parameters

When configuring an OAuth 2 service, you also provide default values for flow parameters.

The *scopes* are keywords representing the type of access that is requested. They are entirely dependent on your own installation. They usually represent access types (read, write, create, delete, etc.).

The *resource* parameter is defined by RFC 8707 but not implemented by many AS. Check compatibility before using it.

*aduneoclientfedid* is only compatible with the *code* response type, the implicit flow being deprecated since 2018.

#### Options

Options describe *aduneoclientfedid*'s behavior outside of the OAuth RFCs.

The only option indicates if HTTPS certificates must be validated.

When testing a production environment, it is advised to verify certificates, to replicate the exact flows.

Other environments typically have specific certificates (self-signed or signed by an internal PKI). Since certificate verification will likely fail, it's best to disable it.

### Access Token Introspection

After an access token has been obtained, it can be introspected.

After clicking on the "Introspect AT" button, a form is displayed in two parts:
- first the parameters defined by RFC 7662 (token and token type hint)
- then the request as it is going to be sent to the authorization server: endpoint, data, authentication parameters

Any change in the first part is reflected on the second (but not the other war around).

During tests, you'll probably have to enter the same information many times (credentials for instance). To help you with that, you can use the internal clipboard.
It keeps all inputs that are entered so that you just have to select it when it's needed again.
The clipboard is opened when clicking the icon on the right of each form field.
By default, passwords are not stored in the clipboard, but a configuration parameter enables this feature.

### Refreshing Access Tokens

If a refresh token (RT) was retrieved during OAuth flow, it can be used to get a new access token.

As with introspection, a two-part form is displayed:
- top form: parameters defined by RFC 6749 (section 6)
- bottom form: the request as it will be sent to the authorization server

### Token Exchange

RFC 8693 defines a way to obtain a new token (ID or access) from an existing valid token (ID or access).

Few authorization servers have implemented it, so check it's available.










## Testing SAML 2

*aduneoclientfedid* is a SAML 2 Service Provider (SP). It simulates an application authenticating to an Identity Provider (IdP).

SAML authentication is only available when the *xmlsec* Python module is installed. Refer to this page for instruction on how to install it: https://pypi.org/project/xmlsec/.
Sometimes it's easy (Windows) sometimes it requires some skills (Ubuntu).

After a successful authentication an OAuth 2 Access Token can be obtained when the IdP is compatible with RFC 7522 
(*Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants*).

### How it works

You will need
- *aduneoclientfedid* installed and started, usually on the local machine
- access to the Identity Provider (the identity server you want to test)
- a test user created on the IdP (along with its password or any other authentication method)
- both *aduneoclientfedid* and the IdP correctly configured (more on that later)

When all of this is done, connect with a web browser to *aduneoclientfedid* main page. Usually https://localhost
(it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes).

The browser will probably display a warning since loading a page from *localhost* is restricted when the connection is
encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you configured a flow in the client as explained in the next part, you can click on the *Login* button next to the name of the configuration you wish to test.

A page is displayed with the default configuration and the default options. You have the liberty to change whatever you need to
perform your test.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the IdP where authentication occurs. Then the browser is redirected to *aduneoclientfedid*.

A page is displayed with the SAML assertion and its validation parameters.

You can then retrieve an access token if needed (and if the IdP is RFC 7522 compliant).

### Configuration

A configuration represents a flow between an Identity Provider and a client. Once a configuration is defined, authentications can be started.

You can define as many configurations as you want, with different IdPs or with the same IdP.

A new configuration is created with the *Add SAML SP* button. A name is required. Choose any name that speaks to you, for it has
no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

A SAML configuration is an exchange of metadata files :
- the SP generates an XML file that is uploaded to the IdP
- the IdP generates an XML file that is uploaded to the SP

While this is the easy way to proceed, it is still possible to enter each parameter individually.

Having gathered information from the IdP, you configure *aduneoclientfedid*
- either by uploading the metadata file, which results in the parameter fields being automatically populated
- or by manually entering it: entity ID, SSO URL and certificate (optionally Single Logout URL)
The certificate must be in PEM format, with or without a header and a footer.

*aduneoclientfedid* generates an XML metadata file based on the information provided in the form:
- SP Entity ID: references the SP. It must be a URI, it is recommended it is a URL
- SP Assertion Consumer Service (ACS) URL: callback URL to *aduneoclientfedid* after authentication. Default is https://localhost/client/saml/login/acs, but you can change it (as long as it stays in the same domain).
- keys and certificate: this information is used to sign the requests. You can either use the default key or provide your own 
(in case you want to replicate an exact real world behavior). Communicate the certificate but **NOT the private key**.
- NameID policy: expected user identifier field returned in the SAML assertion
- Authentication binding: method used to send an authentication request
- Logout binding (optional): method used to send a logout request

Those values are communicated to the IdP either manually or via a metadata file (downloaded through the *Download SP metadata* button)

There obviously needs to be a coherence between the configurations of the SP and the IdP.

Many problems arise because of incompatible NameID policies. NameID is the field with the user's identity. SAML defines different formats and different values.
The easiest format to configure would be the email (*urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress*), but it is not always the best choice for an identifier
(actually, it's a pretty terrible choice in most cases). A better option is an uid present in the identity repository of the organization, which has to be conveyed
in the unspecified format (*urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified*). It often requires a specific configuration on the IdP part.

### SAML Logout

*aduneoclientfedid* implements Single Logout, with the POST or Redirect bindings.

Logout is initiated from the home page.





## General configuration

Some configuration parameters affecting the server behaviour are modified in the configuration file, using your
favorite editor. There is no web console now for these parameters.

The configuration file is named clientfedid.cnf and is in the conf directory that has been created in the current folder
(the one from which the python command has been issued).

It's a JSON file, so be careful of trailing commas. As a reminder, the following syntax is not permitted by JSON:
```console
{
  "param1": "value1",
  "param2": "this will result in an error",
}
```
(remove the last comma to make it JSON compliant)

There are 5 main sections in the configuration file:
- meta: information about the configuration file itself. It only contains the name of the file containing the key used to encrypt
    passwords
- server: HTTP server parameters (port, SSL, etc.)
- preferences
- default
- idps: details the various IdP and client configurations

Any manual change in thre configuration file requires the server to be restarted (Ctrl-C then clientfedid/aduneoclientfedid/python -m aduneoclientfedid).

### meta/key: encryption key file name

All parameters with a name ending with an exclamation point (!) are automatically encrypted (client secrets), using a symmetric key.

A key is automatically generated at first launch and store in a file named clientfedid.key.

It is a good practice to protect this file.

### server/host

Identifies the network card used by the HTTP server.

Using the default localhost makes sure no other machine is (easily...) able to access it.

An empty value ("") opens it to anyone (depending on your local firewall settings).

It can be a name or an IP address.

### server/port

Listening port for the HTTP server.

Default is 443. It might not work on Unix/Linux systems. The easiest fix is to choose a port number greater than 1024 (8443 is a good
candidate).

### server/ssl

Activates HTTPS. Possible values are *on* and *off*.

Since most of the security of OpenID Connect/OAuth 2 relies on HTTPS, it is advisable to leave the default (*on*).

But you may have to turn it off for testing purposes.

### server/ssl_key_file and server/ssl_cert_file

When SSL is activated, these parameters contains the file with
- the SSL private key (*ssl_key_file*), PEM format
- the associated certificate (*ssl_cert_file*), PEM format

If those files are not referenced in the configuration file (which is the default), aduneoclientfedid will automatically create
a key and certificate. Those items are deleted after the server is stopped.

The certificate is self-signed, with server/host as the subject (the FQDN of the machine if server/host is empty).

### preferences/logging/handler

List of logging handlers:
- console: displays logs in the window used to launch the server
- file: adds logs in a file in a directory (*logs*) created alongside *conf* directory.
- webconsole: displays logs in a browser window that can be opened by "console" button on the upper right side of the page, or
automatically when an authentication flow is started

By default, all handlers are activated.

### preferences/open_webconsole:

*on* if the browser window displaying logs is automatically opened every time an authentication flow is started (default).

### preferences/clipboard/encrypt_clipboard

The clipboard stores all texts typed in application forms, to be easily used multiple times without having to enter them each time.

Its content is stored in the *conf* directory.

If *encrypt_clipboard* is *on*, the file is encrypted using *clientfedid.key* as a key. This is the default.

Otherwise, its content is in plain text.

### preferences/clipboard/remember_secrets

Indicates if secrets are stored in the clipboard (default is *off*).
