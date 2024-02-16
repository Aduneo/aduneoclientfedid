/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
clipboardCategories = {
  "authorization_endpoint": "Authorization endpoint",
  "token_endpoint": "Token endpoint",
  "jwks_uri": "JWKS URI",
  "client_id": "Client ID",
  "client_secret": "Client secret",
  "client_secret!": "Client secret",
  "redirect_uri": "Redirect URI",
  "scope": "Scope",
  "resource": "Resource",
  "introspection_endpoint": "Introspection endpoint",
  "access_token": "Access token",
  "request_url": "URL",
}
var clipboardTarget;
var clipboardCategory;

function displayClipboard(imgElement) {
  
  clipboardTarget = null
  
  clipboardSpan = imgElement.parentElement;
  clipboardTD = clipboardSpan.parentElement;
  commonTR = clipboardTD.parentElement;
  inputs = commonTR.getElementsByTagName('input');
  if (inputs.length == 1) {
    clipboardTarget = inputs[0]
  } else {
    textareas = commonTR.getElementsByTagName('textarea');
    if (textareas.length == 1) {
      clipboardTarget = textareas[0]
    }
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
    if ((item.type == 'text') || (item.type == 'password')) {
      clipboardCategory = item.dataset.clipboardcategory;
      if (clipboardCategory && (item.value != '')) {
        if (clipboardCategory == '#name') { clipboardCategory = item.name; }
        if (!values[clipboardCategory]) { values[clipboardCategory] = []; }
        values[clipboardCategory].push(item.value);
      }
    }
  });  
  
  let xhttp = new XMLHttpRequest();
  xhttp.open("POST", "/client/clipboard/update");
  xhttp.setRequestHeader("Content-Type", "application/json");
  xhttp.send(JSON.stringify(values));
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