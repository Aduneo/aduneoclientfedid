/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function getHtmlContinue(method, thisurl, data, menu_id=null) {
  _getHtml(method, thisurl, data, menu_id, true)
}


function getHtml(method, thisurl, data, menu_id=null) {
  _getHtml(method, thisurl, data, menu_id, false)
}


function _getHtml(method, thisurl, data, menu_id=null, continueRequest=false) {

  if (menu_id) {
    document.getElementById(menu_id).style.display = 'none';
  }

  let loop = true;

  while (loop) {
    
    loop = continueRequest;

    textPH = document.getElementById('text_ph');
    textPH.id = '';
    document.getElementById('end_ph').insertAdjacentHTML('beforebegin', '<div id="text_ph"></div>');

    let xhttp = new XMLHttpRequest();
    xhttp.onload = function() {
      if (this.readyState == 4 && this.status == 200) {
        if (xhttp.responseText == 'FIN') {
          loop = false;
        } else {
          document.getElementById('text_ph').innerHTML = xhttp.responseText;
          document.getElementById('end_ph').scrollIntoView();
        }
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


let intervalId = null;
function getHtmlJsonContinue(method, thisurl, data, menu_id=null) {
  _getHtmlJson(method, thisurl, data, menu_id, true);
}


function _getHtmlJson(method, thisurl, data, menu_id=null, continueRequest=false) {

  if (menu_id) {
    document.getElementById(menu_id).style.display = 'none'
  }

  //textPH = document.getElementById('text_ph');
  //textPH.id = '';
  //document.getElementById('end_ph').insertAdjacentHTML('beforebegin', '<div id="text_ph"></div>');

  let xhttp = new XMLHttpRequest();
  xhttp.onload = function() {
    if (this.readyState == 4 && this.status == 200) {
      //console.log(xhttp.response)
      //document.getElementById('text_ph').innerHTML += xhttp.response.html;

      xhttp.response.javascript_include.forEach(include => {
        let scriptEl = document.createElement("script");
        scriptEl.setAttribute("src", include);
        scriptEl.setAttribute("type", "text/javascript");
        document.body.appendChild(scriptEl);
      })
  
      document.getElementById('text_ph').insertAdjacentHTML('beforeend', xhttp.response.html);
      if (xhttp.response.html != '') {
        document.getElementById('end_ph').scrollIntoView();
      }
      
      //xhttp.response.javascript_include.forEach(include => { window.eval('<script src="'+include+'"></script>)'); })
      window.eval(xhttp.response.javascript)
      if (continueRequest) {
        if (xhttp.response.stop === true) {
          if (intervalId) { clearInterval(intervalId); intervalId = null; }
        } else {
          if (intervalId === null) {
            console.log('START')
            intervalId = setInterval(_getHtmlJson, 3000, method, thisurl, data, menu_id, true);
          }
        }
      }
    }
  };
  xhttp.onerror = function(e) {
    console.log(e)
    if (intervalId) { clearInterval(intervalId); intervalId = null; }
  }
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

function reinitFormRequest(domId) {
  
  let fields = document.querySelectorAll('input.'+domId);
  fields.forEach((field) => {
    field.value = field.defaultValue
    field.checked = field.defaultChecked
  });

  eval('initForm_'+domId+'()')

  /*
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
  */
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
    if (document.getElementById(domId+'_d_auth_method').value == 'basic') {
      document.getElementById(domId+'_tr_auth_login').style.display = 'table-row';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'table-row';
    } else if (document.getElementById(domId+'_d_auth_method').value == 'post') {
      document.getElementById(domId+'_tr_auth_login').style.display = 'table-row';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'table-row';
    } else if (document.getElementById(domId+'_d_auth_method').value == 'bearer_token') {
      document.getElementById(domId+'_tr_auth_login').style.display = 'table-row';
      document.getElementById(domId+'_tr_auth_secret').style.display = 'none';
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


function copyFieldValue(imgElement) {

  buttonSpan = imgElement.parentElement;
  buttonTD = buttonSpan.parentElement;
  commonTR = buttonTD.parentElement;
  inputs = commonTR.getElementsByTagName('input');
  if (inputs.length == 1) {
    field = inputs[0];
    field.select();
    document.execCommand("copy");
  }
}

// Nouvelles fonctions

function sendToRequester(formUUID) {

  request_form = document.getElementById('form-'+formUUID);

  // on commence par activer les champs du requêteur
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    if (el.name.startsWith('hr_')) {
      el.disabled = false;
    }
  });

  request_form.submit();
}


/*
  Active/désactive les champs du formulaire (en haut) et de requêteur (en bas) en fonction de la case "Modify request"
*/
function updateModifyRequest(formUUID) {
  
  // flags donnant la visibilité et non l'inactivité
  formState = true; 
  requesterState = false;
  if (document.getElementById(formUUID+'_modify_request').checked) {
    formState = false;
    requesterState = true;
  }

  request_form = document.getElementById('form-'+formUUID);
  
  // on commence par activer ce qui doit l'être (les champs du formulaire ont pour classe formUUID pour une identification plus facile)
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    if (el.name.startsWith('hr_') && requesterState) {
      el.disabled = false;
    } else if (!el.name.startsWith('hr_') && formState) {
      el.disabled = false;
    }
  });
  
  // on active maintenant les éléments en fonction des displayed_when 
  eval("update_form_visibility_"+formUUID+"();");

  // on désactive maintenant le formulaire ou le requêteur
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    if (el.name.startsWith('hr_') && !requesterState) {
      el.disabled = true;
    } else if (!el.name.startsWith('hr_') && !formState) {
      el.disabled = true;
    }
  });
}


function updateFormData(formUUID, requesterFieldValues, paramValues) {
  
  //console.log(requesterFieldValues)
  //console.log(paramValues)
  
  // on commence par vérifier qu'on n'est pas en modification manuelle de la requête
  if (!document.getElementById(formUUID+'_modify_request').checked) {
    
    // on initialise les champs du requêteur
    Object.entries(requesterFieldValues).forEach(([field_name, value]) => {
      field_id = 'hr_'+field_name
      if (document.getElementById(formUUID+'_d_'+field_id)) {
        setFormValue(formUUID, field_id, value);
      }
    });
  
    let formMethod = getFormValue(formUUID, 'hr_form_method')
    let bodyFormat = getFormValue(formUUID, 'hr_body_format')
    let authMethod = getFormValue(formUUID, 'hr_auth_method');

    // les champs pour l'authentification Form sont particuliers
    if ((authMethod == 'form') && (formMethod == 'post' || formMethod == 'redirect')) {
      paramValues[getFormValue(formUUID, 'hr_auth_login_param')] = getFormValue(formUUID, 'hr_auth_login');
      paramValues[getFormValue(formUUID, 'hr_auth_secret_param')] = getFormValue(formUUID, 'hr_auth_secret');
    }
    
  
    
    // on met maintenant à jour les données de la requête finale
    if (formMethod == 'get') {
      request_url = getFormValue(formUUID, 'hr_request_url');
      request_url += (request_url.includes('?') ? '&' : '?');
      request_url += new URLSearchParams(Object.entries(paramValues)).toString();
      setFormValue(formUUID, 'hr_request_url', request_url);
    } else {
      if (bodyFormat == 'x-www-form-urlencoded') {
        setFormValue(formUUID, 'hr_request_data', new URLSearchParams(Object.entries(paramValues)).toString());
      } else if (bodyFormat == 'json') {
        setFormValue(formUUID, 'hr_request_data', JSON.stringify(paramValues, null, 2));
      }
    }
    
    //console.log(method)
  }
}
  

function getFormValue(formUUID, field_id) {
  return document.getElementById(formUUID+'_d_'+field_id).value;
}


function setFormValue(formUUID, field_id, value) {
  el = document.getElementById(formUUID+'_d_'+field_id);
  
  if (el.tagName == 'INPUT' && el.type == 'checkbox') {
    el.checked = value;
  } else {
    el.value = value;
  }
}




