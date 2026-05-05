/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
clipboardCategories = {
  "authorization_endpoint": "Authorization endpoint",
  "token_endpoint": "Token endpoint",
  "userinfo_endpoint": "Userinfo Endpoint",
  "issuer": "Issuer",
  "jwks_uri": "JWKS URI",
  "client_id": "Client ID",
  "client_secret": "Client secret",
  "client_secret!": "Client secret",
  "redirect_uri": "Redirect URI",
  "scope": "Scope",
  "resource": "Resource",
  "introspection_endpoint": "Introspection endpoint",
  "access_token": "Access token",
  "hr_request_url": "URL HTTP",
  "hr_auth_login": "Login HTTP",
  "hr_auth_secret": "Secret HTTP",
  "post_logout_redirect_uri": "Post Logout Redirect URI",
  "idp_entity_id": "IdP entity ID",
  "idp_sso_url": "IdP SSO URL",
  "idp_certificate": "IdP certificate",
  "sp_entity_id": "SP entity ID",
  "sp_acs_url": "SP Assertion Consumer Service URL",
  "nameid_policy": "NameID Policy",
  "sp_private_key": "SP private key",
  "sp_certificate": "SP certificate",
  "idp_slo_url": "IdP Single Logout Service URL",
  "name_id": "NameID",
  "session_index": "Session index",
  "userinfo_endpoint_dns_override": "Userinfo Endpoint DNS override",
  "revocation_endpoint_dns_override": "Revocation endpoint DNS override",
  "introspection_endpoint_dns_override": "Introspection endpoint DNS override",
  "token_endpoint_dns_override":"Token endpoint DNS override",
  "dns_override": "DNS override",
  "grant_type": "Grant Type",
  "subject_token_type": "Subject token type",
  "audience": "Audience",
  "actor_token": "Actor token",
  "actor_token_type": "Actor token type",
  "max_age": "Max Age",
  "ui_locales": "UI Locales",
  "id_token_hint": "ID Token Hint",
  "login_hint": "Login Hint",
  "acr_values": "Authentication Context Class Reference values",
  "end_session_endpoint": "End Session endpoint",
  "state": "State",
  "service_url": "Service URL",
  "cas_server_login_url": "CAS server login URL",
  "cas_server_validate_url": "CAS server validate URL"
}
var clipboardTarget;
var clipboardCategory;

function displayClipboard(imgElement) {
  
  clipboardTarget = null
  
  clipboardSpan = imgElement.parentElement;
  clipboardTD = clipboardSpan.parentElement;
  commonTR = clipboardTD.parentElement;
  inputs = commonTR.getElementsByTagName('input');
  textareas = commonTR.getElementsByTagName('textarea');
  if (textareas.length == 1){
    clipboardTarget = textareas[0];
  }
  else if (inputs.length == 1) {
    clipboardTarget = inputs[0];
  } 
  
  if (clipboardTarget) {
  
    var rect = imgElement.getBoundingClientRect();
    var targetRect = clipboardTarget.getBoundingClientRect();
    
    clipboardCategory = clipboardTarget.dataset.clipboardcategory;
    if (clipboardCategory) {
    
      if (clipboardCategory == '#name') { clipboardCategory = clipboardTarget.name; }
      
      categoryLabel = clipboardCategories[clipboardCategory];
      if (!categoryLabel) { categoryLabel = clipboardCategory; }
      
      document.getElementById('clipboardSpecific').innerHTML = categoryLabel;
      
      modalBackground = document.getElementById('clipboardWindowBackground')
      modal = document.getElementById('clipboardWindow')
      modal.style.left = targetRect.left;
      modal.style.top = window.pageYOffset+targetRect.bottom+4;
      modalBackground.style.visibility = 'visible';
      modal.style.visibility = 'visible';
      
      refreshClipboard(clipboardCategory)
    }
  }
}


function refreshClipboard(category=null) {
  
  clearClipboard();
  
  if (!category) { category = clipboardCategory; }
  
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      jsonResponse = JSON.parse(xhttp.responseText);
      refreshTexts(jsonResponse);
    }
  };
  xhttp.open("GET", "/client/clipboard/get?category="+category, true);
  xhttp.send();
}


function refreshTexts(jsonData) {
  template = document.getElementById('clipboardChoiceTemplate')
  currentButton = template;
  jsonData.forEach(item => {
    newButton = template.cloneNode(true);
    newButton.id = item['id']
    textSpan = newButton.getElementsByClassName('choiceText')[0];
    textSpan.innerText = item['text'];
    currentButton.after(newButton);
    newButton.style.display = 'block'
    currentButton = newButton;
  });
}


function clearClipboard() {
  contentDiv = document.getElementById('clipboardContent');
  children = Array.from(contentDiv.children);
  children.forEach(child => {
    if (child.style.display == 'block') {
      child.remove();
    }
  });
}


function clipboardClickBackground(event) {
  modalBackground = document.getElementById('clipboardWindowBackground');
  if (event.target === modalBackground) {
    closeClipboard();
  }
}


function closeClipboard() {
  modalBackground = document.getElementById('clipboardWindowBackground');
  modal = document.getElementById('clipboardWindow');
  modalBackground.style.visibility = 'hidden';
  modal.style.visibility = 'hidden';
}


function fillClipboard(form) {
  
  values = {};
  
  Array.prototype.forEach.call(form.elements, item => {
    if ((item.type == 'text') || (item.type == 'password') || (item.type == 'textarea') ) {
      clipboardCategory = item.dataset.clipboardcategory;
      if (clipboardCategory && (item.value != '')) {
        if (clipboardCategory == '#name') { clipboardCategory = item.name; }
        if (!values[clipboardCategory]) { values[clipboardCategory] = []; }
        values[clipboardCategory].push(item.value);
      }
    }
  });  
  
  updateClipboard("/client/clipboard/update", JSON.stringify(values));
}

/* Permet à la requête de survivre la redirection lorsque RequesterForm est en mode 'new_page' */
function updateClipboard(url, json_data) {
  navigator.sendBeacon(url, new Blob([json_data], { type: "application/json" }));
}

function selectClipboardText(buttonDiv) {
  textSpan = buttonDiv.getElementsByTagName('span')[0];
  clipboardTarget.value = textSpan.innerText;
  closeClipboard();
}


function removeClipboardText(event, imgElem) {
  event.stopPropagation();

  imgSpan = imgElem.parentNode;
  buttonDiv = imgSpan.parentNode;
  textId = buttonDiv.id
  buttonDiv.remove()
  
  let xhttp = new XMLHttpRequest();
  xhttp.open("GET", "/client/clipboard/remove?id="+textId);
  xhttp.send();
}