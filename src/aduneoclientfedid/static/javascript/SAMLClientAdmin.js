/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function uploadPem(event) {
  
  input = event.target
  
  var reader = new FileReader();
  reader.onload = function() {
    var text = reader.result;
    document.getElementById(input.id.substring(7)).innerHTML = stripPEMHeader(text)
  };
  reader.readAsText(input.files[0]);
}


function stripPEMHeader(text) {
  
  if (text.startsWith('-----')) {
    lines = text.trim().split("\n")
    lines.splice(0, 1)
    lines.splice(-1, 1)
    text = lines.join('').replaceAll("\r", '')
  }
  
  return text
}


function debugMD() {
  xml = "<?xml version=\"1.0\" encoding=\"utf-8\"?><EntityDescriptor ID=\"_38b84776-de37-42f0-b80c-392bc4d12004\" entityID=\"https://sts.windows.net/b20a2822-5260-4ea7-b000-c17131389b33/\" xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\"><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /><SignatureMethod Algorithm=\"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256\" /><Reference URI=\"#_38b84776-de37-42f0-b80c-392bc4d12004\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" /><DigestValue>uUJij+oKQVXM5OLc2yPKhAQviyZX95u/MedijFvoaDQ=</DigestValue></Reference></SignedInfo><SignatureValue>a/uAEoEKFItrccXBkdixafJAYdjr5n8koc99IvoVOTgKYD3/ItC6/ao+rQ64fidCp/kk07l8K5m7PuHZhDQnH5ZIwJ57I0o4gsp27lpscmV51nqqvLpA1F84gCthx8mB/X8L3YpMxNGBg2UWtvv5/yYho1N/ZD1wJ3R+eyU1DYJbdsq50oYhfunS1nmTSNtwIfb7FLEEFtTj/Dpmf4i1TqzVW1JbgO8hyAxINuP1v9mpf8i7W5CjQNK5QCOOMMl95WzBqgTIuynLPkxJ7rhTImq8kBP9SNn5HRLBEk1pYXAL7EycwEQbn6Sj1/iBScmb73hkE0EtdP1iceoD86bF3g==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQNwUNAOhuCYlJ6/2EU7ttcTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMDMwOTU1NTBaFw0yNDAzMDMwOTU1NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtKv3bCYXFGaD4GbnpJXq3bLywojqGtGAEqoDo12O82VGXUjZcTtwPHV8zxtWJ/iWW+ybN4pKtCuaGsaY3io05XUZk95bVl3dBBhReASiJgl2DqVv0M3Z33FCh/yV45owGjGIlQ5nScAwmYfrHR+NCrx1hEyATGMIRfANZ8yYE4Tue91zVabfHLHXB8gS3+/guYh7YZJd/Mcj1Rp2+7K1ay5Jua3m4Z2Gy6mwQ/2ak+CKbNdnUpD2b5/iwfB7pRrP/X56dlp0uGHyIgn++/OBH8gw+oDILlaBK8gxCL6+9bDtcYGpVEWV081spSKe91zd2hv4aYF/G5bnThPMPPfDQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCRlbhtkDjZ12m6t5/c7NV6a/hWDmowKih7Q4NDKpVeq9hAuP8jnvGgrJzZIeuVTi/zJzA0edy22GrvzYavUEhxCjRQ+ERVDASZ1hzFhQS/SR0PWGZh0kjUKqRNdy46yDoggxeFMu+yJJVhyfF66IR9xXS4JI36dGHh4qGh2twV5f5Li8rMYYaHh8N4uRHigPkbAdBLEDCu4CVuNFtD2SAQ+uEhC/wUUW5FdY8UeJbg7ic2cLEQkIuPr6oVnc3nxT6lNkt+LWSJwxwKly5zf7mqNKG6GxyOwnv4Qldq0U1irHV6oeUi2QZeW6GdSMQbG6poIDscODd8T/Hh9VSUxafr</X509Certificate></X509Data></KeyInfo></Signature><RoleDescriptor xsi:type=\"fed:SecurityTokenServiceType\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:fed=\"http://docs.oasis-open.org/wsfed/federation/200706\"><KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQNwUNAOhuCYlJ6/2EU7ttcTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMDMwOTU1NTBaFw0yNDAzMDMwOTU1NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtKv3bCYXFGaD4GbnpJXq3bLywojqGtGAEqoDo12O82VGXUjZcTtwPHV8zxtWJ/iWW+ybN4pKtCuaGsaY3io05XUZk95bVl3dBBhReASiJgl2DqVv0M3Z33FCh/yV45owGjGIlQ5nScAwmYfrHR+NCrx1hEyATGMIRfANZ8yYE4Tue91zVabfHLHXB8gS3+/guYh7YZJd/Mcj1Rp2+7K1ay5Jua3m4Z2Gy6mwQ/2ak+CKbNdnUpD2b5/iwfB7pRrP/X56dlp0uGHyIgn++/OBH8gw+oDILlaBK8gxCL6+9bDtcYGpVEWV081spSKe91zd2hv4aYF/G5bnThPMPPfDQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCRlbhtkDjZ12m6t5/c7NV6a/hWDmowKih7Q4NDKpVeq9hAuP8jnvGgrJzZIeuVTi/zJzA0edy22GrvzYavUEhxCjRQ+ERVDASZ1hzFhQS/SR0PWGZh0kjUKqRNdy46yDoggxeFMu+yJJVhyfF66IR9xXS4JI36dGHh4qGh2twV5f5Li8rMYYaHh8N4uRHigPkbAdBLEDCu4CVuNFtD2SAQ+uEhC/wUUW5FdY8UeJbg7ic2cLEQkIuPr6oVnc3nxT6lNkt+LWSJwxwKly5zf7mqNKG6GxyOwnv4Qldq0U1irHV6oeUi2QZeW6GdSMQbG6poIDscODd8T/Hh9VSUxafr</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:ClaimTypesOffered><auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Name</auth:DisplayName><auth:Description>The mutable display name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Subject</auth:DisplayName><auth:Description>An immutable, globally unique, non-reusable identifier of the user that is unique to the application for which a token is issued.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Given Name</auth:DisplayName><auth:Description>First name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Surname</auth:DisplayName><auth:Description>Last name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/displayname\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Display Name</auth:DisplayName><auth:Description>Display name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/nickname\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Nick Name</auth:DisplayName><auth:Description>Nick name of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationinstant\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Authentication Instant</auth:DisplayName><auth:Description>The time (UTC) when the user is authenticated to Windows Azure Active Directory.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Authentication Method</auth:DisplayName><auth:Description>The method that Windows Azure Active Directory uses to authenticate users.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/objectidentifier\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>ObjectIdentifier</auth:DisplayName><auth:Description>Primary identifier for the user in the directory. Immutable, globally unique, non-reusable.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/tenantid\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>TenantId</auth:DisplayName><auth:Description>Identifier for the user's tenant.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/identityprovider\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>IdentityProvider</auth:DisplayName><auth:Description>Identity provider for the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Email</auth:DisplayName><auth:Description>Email address of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/groups\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Groups</auth:DisplayName><auth:Description>Groups of the user.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/accesstoken\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>External Access Token</auth:DisplayName><auth:Description>Access token issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/expiration\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>External Access Token Expiration</auth:DisplayName><auth:Description>UTC expiration time of access token issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/identity/claims/openid2_id\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>External OpenID 2.0 Identifier</auth:DisplayName><auth:Description>OpenID 2.0 identifier issued by external identity provider.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/claims/groups.link\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>GroupsOverageClaim</auth:DisplayName><auth:Description>Issued when number of user's group claims exceeds return limit.</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/role\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>Role Claim</auth:DisplayName><auth:Description>Roles that the user or Service Principal is attached to</auth:Description></auth:ClaimType><auth:ClaimType Uri=\"http://schemas.microsoft.com/ws/2008/06/identity/claims/wids\" xmlns:auth=\"http://docs.oasis-open.org/wsfed/authorization/200706\"><auth:DisplayName>RoleTemplate Id Claim</auth:DisplayName><auth:Description>Role template id of the Built-in Directory Roles that the user is a member of</auth:Description></auth:ClaimType></fed:ClaimTypesOffered><fed:SecurityTokenServiceEndpoint><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/wsfed</wsa:Address></wsa:EndpointReference></fed:SecurityTokenServiceEndpoint><fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/wsfed</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor><RoleDescriptor xsi:type=\"fed:ApplicationServiceType\" protocolSupportEnumeration=\"http://docs.oasis-open.org/wsfed/federation/200706\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:fed=\"http://docs.oasis-open.org/wsfed/federation/200706\"><KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQNwUNAOhuCYlJ6/2EU7ttcTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMDMwOTU1NTBaFw0yNDAzMDMwOTU1NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtKv3bCYXFGaD4GbnpJXq3bLywojqGtGAEqoDo12O82VGXUjZcTtwPHV8zxtWJ/iWW+ybN4pKtCuaGsaY3io05XUZk95bVl3dBBhReASiJgl2DqVv0M3Z33FCh/yV45owGjGIlQ5nScAwmYfrHR+NCrx1hEyATGMIRfANZ8yYE4Tue91zVabfHLHXB8gS3+/guYh7YZJd/Mcj1Rp2+7K1ay5Jua3m4Z2Gy6mwQ/2ak+CKbNdnUpD2b5/iwfB7pRrP/X56dlp0uGHyIgn++/OBH8gw+oDILlaBK8gxCL6+9bDtcYGpVEWV081spSKe91zd2hv4aYF/G5bnThPMPPfDQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCRlbhtkDjZ12m6t5/c7NV6a/hWDmowKih7Q4NDKpVeq9hAuP8jnvGgrJzZIeuVTi/zJzA0edy22GrvzYavUEhxCjRQ+ERVDASZ1hzFhQS/SR0PWGZh0kjUKqRNdy46yDoggxeFMu+yJJVhyfF66IR9xXS4JI36dGHh4qGh2twV5f5Li8rMYYaHh8N4uRHigPkbAdBLEDCu4CVuNFtD2SAQ+uEhC/wUUW5FdY8UeJbg7ic2cLEQkIuPr6oVnc3nxT6lNkt+LWSJwxwKly5zf7mqNKG6GxyOwnv4Qldq0U1irHV6oeUi2QZeW6GdSMQbG6poIDscODd8T/Hh9VSUxafr</X509Certificate></X509Data></KeyInfo></KeyDescriptor><fed:TargetScopes><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>https://sts.windows.net/b20a2822-5260-4ea7-b000-c17131389b33/</wsa:Address></wsa:EndpointReference></fed:TargetScopes><fed:ApplicationServiceEndpoint><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/wsfed</wsa:Address></wsa:EndpointReference></fed:ApplicationServiceEndpoint><fed:PassiveRequestorEndpoint><wsa:EndpointReference xmlns:wsa=\"http://www.w3.org/2005/08/addressing\"><wsa:Address>https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/wsfed</wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint></RoleDescriptor><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><KeyDescriptor use=\"signing\"><KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><X509Data><X509Certificate>MIIC8DCCAdigAwIBAgIQNwUNAOhuCYlJ6/2EU7ttcTANBgkqhkiG9w0BAQsFADA0MTIwMAYDVQQDEylNaWNyb3NvZnQgQXp1cmUgRmVkZXJhdGVkIFNTTyBDZXJ0aWZpY2F0ZTAeFw0yMTAzMDMwOTU1NTBaFw0yNDAzMDMwOTU1NDNaMDQxMjAwBgNVBAMTKU1pY3Jvc29mdCBBenVyZSBGZWRlcmF0ZWQgU1NPIENlcnRpZmljYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwtKv3bCYXFGaD4GbnpJXq3bLywojqGtGAEqoDo12O82VGXUjZcTtwPHV8zxtWJ/iWW+ybN4pKtCuaGsaY3io05XUZk95bVl3dBBhReASiJgl2DqVv0M3Z33FCh/yV45owGjGIlQ5nScAwmYfrHR+NCrx1hEyATGMIRfANZ8yYE4Tue91zVabfHLHXB8gS3+/guYh7YZJd/Mcj1Rp2+7K1ay5Jua3m4Z2Gy6mwQ/2ak+CKbNdnUpD2b5/iwfB7pRrP/X56dlp0uGHyIgn++/OBH8gw+oDILlaBK8gxCL6+9bDtcYGpVEWV081spSKe91zd2hv4aYF/G5bnThPMPPfDQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCRlbhtkDjZ12m6t5/c7NV6a/hWDmowKih7Q4NDKpVeq9hAuP8jnvGgrJzZIeuVTi/zJzA0edy22GrvzYavUEhxCjRQ+ERVDASZ1hzFhQS/SR0PWGZh0kjUKqRNdy46yDoggxeFMu+yJJVhyfF66IR9xXS4JI36dGHh4qGh2twV5f5Li8rMYYaHh8N4uRHigPkbAdBLEDCu4CVuNFtD2SAQ+uEhC/wUUW5FdY8UeJbg7ic2cLEQkIuPr6oVnc3nxT6lNkt+LWSJwxwKly5zf7mqNKG6GxyOwnv4Qldq0U1irHV6oeUi2QZeW6GdSMQbG6poIDscODd8T/Hh9VSUxafr</X509Certificate></X509Data></KeyInfo></KeyDescriptor><SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/saml2\" /><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/saml2\" /><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/saml2\" /></IDPSSODescriptor></EntityDescriptor>"
  parseIdPMetadata(xml)
}


function uploadIdPMetadata(event) {
  
  input = event.target
  
  var reader = new FileReader();
  reader.onload = function() {
	parseIdPMetadata(reader.result)
  };
  reader.readAsText(input.files[0]);
}


function parseIdPMetadata(xml, cfiForm) {
  
  const parser = new DOMParser();
  const dom = parser.parseFromString(xml, "application/xml");
  root = dom.documentElement
  
  xmlns = 'urn:oasis:names:tc:SAML:2.0:metadata'
  
  // Entity ID
  entityIDAttr = root.attributes.getNamedItem('entityID')
  cfiForm.setFieldValue('idp_entity_id', entityIDAttr.value)
  
  // IDPSSODescriptor
  IDPSSODescriptorEl = dom.getElementsByTagNameNS(xmlns, 'IDPSSODescriptor')[0]
  
  // SSO URL
  fetchServiceUrl(cfiForm, IDPSSODescriptorEl.getElementsByTagNameNS(xmlns, 'SingleSignOnService'), 'idp_sso_url', 'authentication_binding', 'idp_authentication_binding_capabilities')
  
  // Logout URL
  fetchServiceUrl(cfiForm, IDPSSODescriptorEl.getElementsByTagNameNS(xmlns, 'SingleLogoutService'), 'idp_slo_url', 'logout_binding', 'idp_logout_binding_capabilities')
  
  // Certificate
  certificateEl = IDPSSODescriptorEl.querySelector('X509Certificate')
  certificate = certificateEl.childNodes[0].nodeValue
  cfiForm.setFieldValue('idp_certificate', certificate.trim().replaceAll("\n", '').replaceAll("\r", ''))

}


function fetchServiceUrl(cfiForm, xmlServices, serviceUrlInput, bindingSelect, capabilitiesInput) {
  
  cfiForm.setFieldValue(serviceUrlInput, '')
  for (var i = 0; i < xmlServices.length; i++) {
    xmlService = xmlServices[i];
    bindingAttr = xmlService.attributes.getNamedItem('Binding');
    
    var selectBinding = false
    if (i == 0) selectBinding = true
    if (bindingAttr.value == preferredBinding) selectBinding = true
    if (selectBinding) {
      cfiForm.setFieldValue(serviceUrlInput, xmlService.attributes.getNamedItem('Location').value)
    }
  }

  if (capabilitiesInput) {
    var capabilities = ''
    for (var i = 0; i < xmlServices.length; i++) {
      
      xmlService = xmlServices[i];
      bindingAttr = xmlService.attributes.getNamedItem('Binding');
      if (capabilities != '') capabilities += '\t';
      capabilities += bindingAttr.value;
    }
    cfiForm.setFieldValue(capabilitiesInput, capabilities);
  }

  bindingSelectElement = cfiForm.getField(bindingSelect);
  if (bindingSelectElement) {
    var preferredBinding = bindingSelectElement.value;
    
    removeSelectOptions(bindingSelectElement)
    
    for (var i = 0; i < xmlServices.length; i++) {
      
      xmlService = xmlServices[i];
      bindingAttr = xmlService.attributes.getNamedItem('Binding');
      var option = document.createElement('option');
      option.value = option.text = bindingAttr.value;
      bindingSelectElement.add(option);
      
      var selectBinding = false
      if (i == 0) selectBinding = true
      if (bindingAttr.value == preferredBinding) selectBinding = true
      if (selectBinding) {
        bindingSelectElement.value = bindingAttr.value
        cfiForm.setFieldValue(serviceUrlInput, xmlService.attributes.getNamedItem('Location').value)
      }
    }
  }
}


function removeSelectOptions(selectElement) {
  
  var l = selectElement.options.length - 1;
  for(var i = l; i >= 0; i--) {
    selectElement.remove(i);
  }
}


function downloadSPMetadata(cfiForm) {
  
  filename = cfiForm.getFieldValue('app_id');
  if (filename == '') {
    filename = cfiForm.getFieldValue('app_name');
  }
  if (filename == '') {
    filename = 'spMetadata'
  }

  let form = document.createElement("form");
  form.setAttribute("method", "POST");
  form.setAttribute("action", "downloadSPMetadata");

  
  let input = document.createElement("input");
  input.setAttribute("type", "hidden");
  input.setAttribute("name", "filename");
  input.setAttribute("value", filename);
  form.appendChild(input);

  addValueToForm(form, 'sp_entity_id')
  addValueToForm(form, 'sp_acs_url')
  addValueToForm(form, 'sp_slo_url')
  addValueToForm(form, 'sp_key_configuration')
  addValueToForm(form, 'sp_private_key')
  addValueToForm(form, 'sp_certificate')
  addValueToForm(form, 'nameid_policy')
  addValueToForm(form, 'authentication_binding')
  addValueToForm(form, 'logout_binding')
  addCheckedToForm(form, 'sign_auth_request')
  addCheckedToForm(form, 'sign_logout_request')

  document.body.appendChild(form);
  form.submit()
  document.body.removeChild(form);    
}

function addValueToForm(form, inputName) {
  let input = document.createElement("input");
  input.setAttribute("type", "hidden");
  input.setAttribute("name", inputName);
  input.setAttribute("value", cfiForm.getFieldValue(inputName));
  form.appendChild(input);
}


function addCheckedToForm(form, inputName) {
  let input = document.createElement("input");
  input.setAttribute("type", "hidden");
  input.setAttribute("name", inputName);
  input.setAttribute("value", cfiForm.getField(inputName).checked ? "true" : "false");
  form.appendChild(input);
}


function generateSPKeys(cfiForm) {
  
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      jsonResponse = JSON.parse(xhttp.responseText);
      cfiForm.setFieldValue('sp_private_key', stripPEMHeader(jsonResponse.private_key));
      cfiForm.setFieldValue('sp_certificate', stripPEMHeader(jsonResponse.certificate));
    }
  };
  xhttp.open("GET", "/generatecertificate", true);
  xhttp.send();
}


function downloadSpecificCertificate(cfiForm) {

  certificate = cfiForm.getFieldValue('sp_certificate')
  if (!certificate.startsWith('-----BEGIN CERTIFICATE-----')) {
    segments = certificate.match(/.{1,64}/g)
    certificate = '-----BEGIN CERTIFICATE-----\\n'+segments.join('\\n')+'\\n-----END CERTIFICATE-----'
  }
  
  var element = document.createElement('a');
  element.setAttribute('href', 'data:application/x-pem-file;charset=utf-8,' + encodeURIComponent(certificate));
  element.setAttribute('download', 'aduneo.crt');

  element.style.display = 'none';
  document.body.appendChild(element);

  element.click();

  document.body.removeChild(element);
}
