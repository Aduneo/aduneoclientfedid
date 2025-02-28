/**
 * @license
 * Copyright 2025 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function updateForFlow(cfiForm) {

  flow = cfiForm.getFieldValue('oauth_flow');

  if (flow == 'authorization_code' || flow == 'authorization_code_pkce') {
    cfiForm.setFieldValue('flow_url', cfiForm.getFieldValue('authorization_endpoint'))
    cfiForm.setFieldValue('flow_http_method', 'redirect')
  } else if (flow == 'client_credentials') {
    cfiForm.setFieldValue('flow_url', cfiForm.getFieldValue('token_endpoint'))
    cfiForm.setFieldValue('flow_http_method', 'post')
    cfiForm.setFieldValue('grant_type', 'client_credentials')
  } else if (flow == 'resource_owner_password_credentials') {
    cfiForm.setFieldValue('flow_url', cfiForm.getFieldValue('token_endpoint'))
    cfiForm.setFieldValue('flow_http_method', 'post')
    cfiForm.setFieldValue('grant_type', 'password')
  }
}


function generateOAuth2Request(paramValues, cfiForm) {

  let filteredParamValues = {};

  if (cfiForm.getField('oauth_flow').value == 'authorization_code' || cfiForm.getField('oauth_flow').value == 'authorization_code_pkce') {
    for (param of ['client_id', 'redirect_uri', 'scope', 'response_type', 'state']) { if (param in paramValues) filteredParamValues[param] = paramValues[param]; }
  }

  if (cfiForm.getField('oauth_flow').value == 'authorization_code_pkce') {
    for (param of ['code_challenge_method', 'code_challenge']) { if (param in paramValues) filteredParamValues[param] = paramValues[param]; }
    
    if (cfiForm.getField('code_challenge_method').value == 'plain') {
      filteredParamValues['code_challenge'] = cfiForm.getField('code_verifier').value;
    }
  }

  if (cfiForm.getField('oauth_flow').value == 'client_credentials') {
    for (param of ['grant_type', 'scope']) { if (param in paramValues) filteredParamValues[param] = paramValues[param]; }
  }
  
  if (cfiForm.getField('oauth_flow').value == 'resource_owner_password_credentials') {
    for (param of ['grant_type', 'scope', 'username', 'password']) { if (param in paramValues) filteredParamValues[param] = paramValues[param]; }
  }
  
  return filteredParamValues;
}