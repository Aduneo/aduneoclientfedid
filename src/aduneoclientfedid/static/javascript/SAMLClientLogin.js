/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function updateAuthenticationRequest(cfiForm) {

  var request = "<samlp:AuthnRequest\r\n"
  request += "  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \r\n"
  request += "  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \r\n"
  request += "  ID=\"{requestId}\" \r\n"
  request += "  Version=\"2.0\" \r\n"
  request += "  ProviderName=\"{provider_name}\" \r\n"
  request += "  IssueInstant=\"{timestamp}\" \r\n"
  request += "  Destination=\"{destination}\" \r\n"
  request += "  ProtocolBinding=\"{protocol_binding}\" \r\n"
  request += "  AssertionConsumerServiceURL=\"{acs_url}\"> \r\n"
  request += "\r\n"
  request += "  <saml:Issuer>{sp_id}</saml:Issuer> \r\n"
  request += "  <samlp:NameIDPolicy Format=\"{nameid_policy}\" AllowCreate=\"true\"/> \r\n"
  request += "</samlp:AuthnRequest>"

  request = request.replace('{requestId}', cfiForm.getFieldValue('request_id'));
  request = request.replace('{provider_name}', cfiForm.getFieldValue('name'));
  request = request.replace('{timestamp}', (new Date()).toISOString());
  request = request.replace('{destination}', cfiForm.getFieldValue('idp_sso_url'));
  request = request.replace('{protocol_binding}', cfiForm.getFieldValue('authentication_binding'));
  request = request.replace('{acs_url}', cfiForm.getFieldValue('sp_acs_url'));
  request = request.replace('{sp_id}', cfiForm.getFieldValue('sp_entity_id'));
  request = request.replace('{nameid_policy}', cfiForm.getFieldValue('nameid_policy'));
  
  cfiForm.setFieldValue('authentication_request', request);
}

