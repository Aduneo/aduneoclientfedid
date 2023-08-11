Testing SAML 2
==============

*aduneoclientfedid* is a SAML 2 Service Provider (SP). It simulates an application authenticating to an Identity Provider (IdP).

SAML authentication is only available when the *xmlsec* Python module is installed. Refer to this page for instruction on how to install it: https://pypi.org/project/xmlsec/. Sometimes it's easy (Windows) sometimes it requires some skills (Ubuntu).

After a successful authentication an OAuth 2 Access Token can be obtained when the IdP is compatible with RFC 7522 (*Security Assertion Markup Language (SAML) 2.0 Profile for OAuth 2.0 Client Authentication and Authorization Grants*).

How it works
------------

You will need:

* *aduneoclientfedid* installed and started, usually on the local machine
* Access to the Identity Provider (the identity server you want to test)
* A test user created on the IdP (along with its password or any other authentication method)
* Both *aduneoclientfedid* and the IdP correctly configured (more on that later)
  
When all of this is done, connect with a web browser to *aduneoclientfedid* main page. Usually https://localhost.

.. note::
    it's possible to install it on a different machine, to change to port, and to deactivate HTTPS for testing purposes

The browser will probably display a warning since loading a page from *localhost* is restricted when the connection is encrypted. Bypass the warning, or change the configuration to switch to unencrypted or to connect to a real IP address.

Once you configured a flow in the client as explained in the next part, you can click on the *Login* button next to the name of the configuration you wish to test.

A page is displayed with the default configuration and the default options. You have the liberty to change whatever you need to perform your test.

The authentication flow is started when you click on *Send to IdP*.

The browser is redirected to the IdP where authentication occurs. Then the browser is redirected to *aduneoclientfedid*.

A page is displayed with the SAML assertion and its validation parameters.

You can then retrieve an access token if needed (and if the IdP is RFC 7522 compliant).

Configuration
-------------

A configuration represents a flow between an Identity Provider and a client. Once a configuration is defined, authentications can be started.

You can define as many configurations as you want, with different IdPs or with the same IdP.

A new configuration is created with the *Add SAML SP* button. A name is required. Choose any name that speaks to you, for it has no technical meaning. It is obviously advised that the name includes references to the OP and to what you are to test.

A SAML configuration is an exchange of metadata files:

* The SP generates an XML file that is uploaded to the IdP
* The IdP generates an XML file that is uploaded to the SP
  
While this is the easy way to proceed, it is still possible to enter each parameter individually.

Having gathered information from the IdP, you configure *aduneoclientfedid*

* Either by uploading the metadata file, which results in the parameter fields being automatically populated
* Or by manually entering it: entity ID, SSO URL and certificate (optionally Single Logout URL) The certificate must be in PEM format, with or without a header and a footer.

*aduneoclientfedid* generates an XML metadata file based on the information provided in the form:

* SP Entity ID: references the SP. It must be a URI, it is recommended it is a URL
* SP Assertion Consumer Service (ACS) URL: callback URL to aduneoclientfedid after authentication. Default is https://localhost/client/saml/login/acs, but you can change it (as long as it stays in the same domain).
* keys and certificate: this information is used to sign the requests. You can either use the default key or provide your own (in case you want to replicate an exact real world behavior).

.. Warning::
    Communicate the certificate but NOT the private key

* NameID policy: expected user identifier field returned in the SAML assertion
* Authentication binding: method used to send an authentication request
* Logout binding (optional): method used to send a logout request
  
Those values are communicated to the IdP either manually or via a metadata file (downloaded through the *Download SP metadata* button)

There obviously needs to be a coherence between the configurations of the SP and the IdP.

Many problems arise because of incompatible NameID policies. NameID is the field with the user's identity. SAML defines different formats and different values. The easiest format to configure would be the email (*urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress*), but it is not always the best choice for an identifier (actually, it's a pretty terrible choice in most cases). 
A better option is an uid present in the identity repository of the organization, which has to be conveyed in the unspecified format (*urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified*). It often requires a specific configuration on the IdP part.

SAML Logout
-----------

*aduneoclientfedid* implements Single Logout, with the POST or Redirect bindings.

Logout is initiated from the home page.