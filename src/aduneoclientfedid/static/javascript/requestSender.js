/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function getHtml(method, thisurl, data, menu_id=null) {

  if (menu_id) {
    document.getElementById(menu_id).style.display = 'none'
  }

  textPH = document.getElementById('text_ph');
  textPH.id = '';
  document.getElementById('end_ph').insertAdjacentHTML('beforebegin', '<div id="text_ph"></div>');

  let xhttp = new XMLHttpRequest();
  xhttp.onload = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById('text_ph').innerHTML = xhttp.responseText;
      document.getElementById('end_ph').scrollIntoView()
    }
  };
  xhttp.open(method, thisurl);
  if (method === 'GET') {
    xhttp.send();
  } else {
    let formData = new FormData();
    for (const [key, value] of Object.entries(data)) {
      formData.append(key, value);
    }
    xhttp.setRequestHeader('Content-Type','application/x-www-form-urlencoded')
    xhttp.send(new URLSearchParams(formData));
  }
}

function getHtmlJson(method, thisurl, data, menu_id=null) {

  if (menu_id) {
    document.getElementById(menu_id).style.display = 'none'
  }

  textPH = document.getElementById('text_ph');
  textPH.id = '';
  document.getElementById('end_ph').insertAdjacentHTML('beforebegin', '<div id="text_ph"></div>');

  let xhttp = new XMLHttpRequest();
  xhttp.onload = function() {
    if (this.readyState == 4 && this.status == 200) {
      document.getElementById('text_ph').innerHTML = xhttp.response.html;
      document.getElementById('end_ph').scrollIntoView()
      window.eval(xhttp.response.javascript)
    }
  };
  xhttp.responseType = 'json';
  xhttp.open(method, thisurl);
  if (method === 'GET') {
    xhttp.send();
  } else {
    let formData = new FormData();
    for (const [key, value] of Object.entries(data)) {
      formData.append(key, value);
    }
    xhttp.setRequestHeader('Content-Type','application/x-www-form-urlencoded')
    xhttp.send(new URLSearchParams(formData));
  }
}


function get_form_value_with_dom(domId, input_name) {
  return document.getElementById(domId+'_d_'+input_name).value;
}

function reinitRequest(domId) {
  
  let fields = document.querySelectorAll('input.'+domId);
  fields.forEach((field) => {
    field.value = field.defaultValue
    field.checked = field.defaultChecked
  });
  
  document.getElementById(domId+'_d_url').value = document.getElementById(domId+'_d_url').defaultValue
  if (document.getElementById(domId+'_d_data')) {
    eval('f_'+domId+'_update()')
  }
  if (document.getElementById(domId+'_d_auth_method')) {
    authMethodSelect = document.getElementById(domId+'_d_auth_method')
    Array.from(authMethodSelect.options, (opt => { opt.selected = opt.defaultSelected; } ));
    changeRequestHTTPAuth(domId)
  }
  document.getElementById(domId+'_d_verify_cert').checked = document.getElementById(domId+'_d_verify_cert').defaultChecked
}

function changeRequestHTTPAuth(domId) {
  if (document.getElementById(domId+'_d_auth_method')) {
    if (document.getElementById(domId+'_d_auth_method').value == 'Basic') {
      document.getElementById(domId+'_tr_auth_login').style.display = 'table-row';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'table-row';
    } else if (document.getElementById(domId+'_d_auth_method').value == 'POST') {
      document.getElementById(domId+'_tr_auth_login').style.display = 'table-row';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'table-row';
    } else {
      document.getElementById(domId+'_tr_auth_login').style.display = 'none';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'none';
    }
    eval('f_'+domId+'_update()')
  }
}

function sendRequest(domId) {
  
  document.getElementById(domId+'_button_bar').style.display = 'none';
  document.getElementById(domId+'_send_notification').style.display = 'block';
  
  callParameters = {};
  ['url', 'data', 'auth_method', 'auth_login', 'auth_secret'].forEach(function(item, index) {
    dataId = domId+'_d_'+item;
    if (document.getElementById(dataId)) {
      callParameters[item] = document.getElementById(dataId).value;
    }
  });
  ['verify_cert'].forEach(function(item, index) {
    dataId = domId+'_d_'+item;
    callParameters[item] = document.getElementById(dataId).checked;
  });
  
  senderUrl = document.getElementById(domId+"_sender_url").value;
  method = document.getElementById(domId+"_method").value;
  context = document.getElementById(domId+"_context").value;

  data = {"method": method, "context": context, "callParameters": JSON.stringify(callParameters)};
  getHtml("POST", senderUrl, data);
  
  fillClipboard(document.getElementById('form-'+domId))
}


function cancelRequest(domId, contextId) {
  
  document.getElementById(domId+'_button_bar').style.display = 'none';
  getHtml("GET", '/client/flows/cancelrequest?contextid='+contextId);
}