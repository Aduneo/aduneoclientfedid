/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function updateLogoutRequest(cfiForm) {

  var request = "<samlp:LogoutRequest\r\n"
  request += "  xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" \r\n"
  request += "  xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" \r\n"
  request += "  ID=\"{requestId}\" \r\n"
  request += "  Version=\"2.0\" \r\n"
  request += "  IssueInstant=\"{timestamp}\" \r\n"
  request += "  Destination=\"{destination}\"> \r\n"
  request += "\r\n"
  request += "  <saml:Issuer>{spId}</saml:Issuer> \r\n"
  request += "  <saml:NameID Format=\"{nameIdFormat}\">{nameId}</saml:NameID> \r\n"
  request += "  <samlp:SessionIndex>{sessionIndex}</samlp:SessionIndex> \r\n"
  request += "</samlp:LogoutRequest>"

  request = request.replace('{requestId}', cfiForm.getFieldValue('request_id'));
  request = request.replace('{timestamp}', (new Date()).toISOString());
  request = request.replace('{destination}', cfiForm.getFieldValue('idp_slo_url'));
  request = request.replace('{spId}', cfiForm.getFieldValue('sp_entity_id'));
  request = request.replace('{nameId}', cfiForm.getFieldValue('name_id'));
  request = request.replace('{nameIdFormat}', cfiForm.getFieldValue('name_id_format'));
  request = request.replace('{sessionIndex}', cfiForm.getFieldValue('session_index'));
  
  cfiForm.setFieldValue('logout_request', request);
}
