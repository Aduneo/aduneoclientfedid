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





let includeJavascript = (include) => {
  return new Promise((resolve, reject) => {

    let scriptEl = document.createElement("script");
    document.body.appendChild(scriptEl);
    scriptEl.onload = resolve;
    scriptEl.src = include;
    scriptEl.type = "text/javascript";
  });
}


let intervalId = null;
let firstBlock = true;
function getHtmlJsonContinue(method, thisurl, data, menu_id=null, notificationId=null) {
  _getHtmlJson(method, thisurl, data, menu_id, true, notificationId);
}
// pour le pas charger plusieurs fois un include Javascript
let javascriptIncludes = [];

/*
    - notificationId : identifiant DOM de la notification "sending" que l'on masque dès que le résultat arrive ou en cas d'erreur
*/
function _getHtmlJson(method, thisurl, data, menu_id=null, continueRequest=false, notificationId=null) {

  let addElements = async (xhttp) => {

    if (xhttp.readyState == 4 && xhttp.status == 200) {

      if (xhttp.response.action == 'redirect') {
        // redirection
        window.location = xhttp.response.url
        
      } else if (xhttp.response.action == 'add_content') {
        // ajout de contenu dans la page continue

        if (notificationId) {
          document.getElementById(notificationId).style.display = 'none';
        }

        for (include of xhttp.response.javascript_include) {
          if (!javascriptIncludes.includes(include)) {
            await includeJavascript(include);
            javascriptIncludes.push(include);
          }
        }
    
        if (xhttp.response.html != '') {
          document.getElementById('text_ph').insertAdjacentHTML('beforeend', xhttp.response.html);
          if (!firstBlock) {
            document.getElementById('end_ph').scrollIntoView();
          }
        }
        
        //console.log(xhttp.response.javascript)
        window.eval(xhttp.response.javascript);

        if (continueRequest) {
          if (xhttp.response.stop === true) {
            if (intervalId) { clearInterval(intervalId); intervalId = null; }
            if (!firstBlock) {
              // on scroll pour mettre le haut du block en haut de la page
              panelTop = document.getElementById('panelTop')
              if (panelTop) {
                // Scroll
                panelTop.scrollIntoView();
                panelTop.remove();
              }
            }
            document.getElementById('text_ph').insertAdjacentHTML('beforeend', '<span id="panelTop"></span>');
            firstBlock = false;
          } else {
            if (intervalId === null) {
              intervalId = setInterval(_getHtmlJson, 500, method, thisurl, data, null, true, null);
            }
          }
        }
      } else {
        console.log("Unknown action "+xhttp.response.action)
      }
    }
  }

  if (menu_id) {
    document.getElementById(menu_id).style.display = 'none'
  }

  //textPH = document.getElementById('text_ph');
  //textPH.id = '';
  //document.getElementById('end_ph').insertAdjacentHTML('beforebegin', '<div id="text_ph"></div>');

  let xhttp = new XMLHttpRequest();
  xhttp.onload = () => { addElements(xhttp); };
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
    field.value = field.defaultValue;
    field.checked = field.defaultChecked;
  });
  fields = document.querySelectorAll('textarea.'+domId);
  fields.forEach((field) => {
    field.value = field.defaultValue;
  });
  

  eval('initForm_'+domId+'()');
  eval('if (typeof updateRequest_'+domId+' === "function") { updateRequest_'+domId+'(); }');
  

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
function sendToRequester_newPage(formUUID) {

  request_form = document.getElementById('form-'+formUUID);

  // on active tous les éléments du formulaire
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    el.disabled = false;
  });

  document.getElementById(formUUID+'_button_bar').style.display = 'none';
  document.getElementById(formUUID+'_send_notification').style.display = 'block';

  fillClipboard(request_form)

  request_form.submit();
}


function sendToRequester_api(formUUID) {

  request_form = document.getElementById('form-'+formUUID);

  /* ce qu'il y avait avant, mais je ne pense pas que ce soit pertinent. Je laisse en commentaire au cas où

  // on commence par activer les champs du requêteur
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    if (el.name.startsWith('hr_')) {
      el.disabled = false;
    }
  });

  request_form.submit();
  
  */
  
  // on récupère tous les éléments du formulaire - peut-être uniquement ceux qui sont actifs ?
  let data = {};
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    if (el.type == 'checkbox') {
      // pour imiter le comportement d'un formulaire normal, on ne transmet pas les cases qui ne sont pas cochées
      if (el.checked) {
        data[el.name] = 'on';
      }
    } else {
      data[el.name] = el.value;
    }
    el.disabled = true;
  });

  // TODO : généraliser la notification d'envoi de la requête
  document.getElementById(formUUID+'_send_notification').style.display = 'block';

  fillClipboard(request_form)

  fetchContent('POST', request_form.action, data, formUUID+'_button_bar', formUUID+'_send_notification');
}


function cancelRequester_api(formUUID, cancelURL) {

  request_form = document.getElementById('form-'+formUUID);

  // on récupère tous les éléments du formulaire - peut-être uniquement ceux qui sont actifs ?
  data = {};
  request_form.querySelectorAll('.'+formUUID).forEach(el => {
    data[el.name] = el.value;
    el.disabled = true;
  });

  fetchContent('GET', cancelURL, null, formUUID+'_button_bar');
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
      if (Object.keys(paramValues).length > 0) {
        request_url += (request_url.includes('?') ? '&' : '?');
        request_url += new URLSearchParams(Object.entries(paramValues)).toString();
      }
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
    el.dispatchEvent(new Event('change'));
  } else {
    el.value = value;
    // on déchenche des événements de changement pour diffusion des modifications
    if (el.type == 'text' || el.type == 'textarea') {
      el.dispatchEvent(new Event('keyup'));
    } else {
      el.dispatchEvent(new Event('change'));
    }
  }
}

/*
  dans une page continue, va chercher du contenu pour l'ajouter à la suite de la page courante
  
  Cette fonction est appelée dans un panel de menu dans une page continue à ajout progressif de contenu :
  - le polling de récupération de contenu a été arrêté
  - le menu est masqué (du moins si l'identifiant de la div le contenant a été donné)
  - la page servant le contenu est invoquée
  - le contenu en tant que tel est récupéré par les mécanismes de page continue (polling du buffer ContiunousPage)
  
  En cas d'erreur, une alerte est affichée et le menu est réaffiché
 
  Exemple d'appel :
    self.add_html('<span onClick="fetchContent(\'GET\',\'userinfo?contextid='+urllib.parse.quote(context_id)+'\', \'\', \''+self.hreq.continuous_page_id+'\', \''+menu_id+'\')" class="button">Userinfo</span>')
 
  Args:
    - method : méthode de la requête (GET ou POST)
    - thisurl : URL où récupérer le Content-Type
    - data : données à envoyer dans le corps du message
    - menuId : identifiant DOM du menu depuis lequel a été invoquée la récupération, afin de pouvoir masquer le menu (facultatif)
    - notificationId : identifiant DOM de la notification "sending" que l'on masque dès que le résultat arrive ou en cas d'erreur
  
*/
function fetchContent(method, thisurl, data, menuId=null, notificationId=null) {
  
  let xhttp = new XMLHttpRequest();
  xhttp.onload = function() {
    if (this.readyState == 4 && this.status == 200) {
      //console.log(xhttp.response)
    }
  };
  xhttp.onerror = function(e) {
    alert(e)
    if (menuId) {
      document.getElementById(menuId).style.display = 'block';
    }
    if (notificationId) {
      document.getElementById(notificationId).style.display = 'none';
    }
  }
  xhttp.open(method, thisurl);
  xhttp.setRequestHeader('CpId', continuousPageId)
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
  
  getHtmlJsonContinue("GET", "/continuouspage/poll?cp_id="+continuousPageId, data, menuId, notificationId);
}


// Appelée par IdpClientAdmin pour afficher / masquer les paramètres des clients
//   Les libellés du bouton doivent être mis dans les attributs displayLabel et hideLabel de l'élement bouton
//   Exemple : <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">
//   panelId est l'identifiant de l'élément à afficher / masquer
function togglePanel(buttonEl, panelId) {
  
  panelEl = document.getElementById(panelId);
  if (panelEl) {
    if (panelEl.style.display == 'none') {
      panelEl.style.display = 'block';
      label = buttonEl.getAttribute('hideLabel');
      if (!label) label = 'Hide';
      buttonEl.innerHTML = label;
    } else {
      panelEl.style.display = 'none'
      label = buttonEl.getAttribute('displayLabel');
      if (!label) label = 'Display';
      buttonEl.innerHTML = label;
    }
  }
}


// Appelée par open_list pour copier, quand elle change, la valeur du select vers l'input text
function openlist_change(event) {
  selectEl = event.target;
  if (selectEl.value == '#type_value') {
    selectEl.nextElementSibling.value = '';
    selectEl.nextElementSibling.focus();
  } else {
    selectEl.nextElementSibling.value = selectEl.value; 
  }
  selectEl.nextElementSibling.dispatchEvent(new Event('keyup'));
}



function CfiForm(formId, thisFieldId) {
  this.formId = formId;
  this.thisFieldId = thisFieldId;
}


CfiForm.prototype.getThisField = function () {
  return document.getElementById(this.formId+'_d_'+this.thisFieldId);
};


CfiForm.prototype.getThisFieldValue = function () {
  return this.getThisField().value;
};


CfiForm.prototype.setThisFieldValue = function (value) {
  this.setFieldValue(this.thisFieldId, value);
};


CfiForm.prototype.getField = function (fieldId) {
  return document.getElementById(this.formId+'_d_'+fieldId);
};


CfiForm.prototype.setFieldValue = function (fieldId, value) {
  
  field = this.getField(fieldId)
  
  field.value = value;
  
  if (field.type == 'text' || field.type == 'textarea') {
    field.dispatchEvent(new Event('keyup'));
  } else {
    field.dispatchEvent(new Event('change'));
  }
};


CfiForm.prototype.getFieldValue = function (fieldId) {
  field = this.getField(fieldId)
  return field.value;
};


CfiForm.prototype.getTable = function (tableId) {
  eval("var tables = tables_"+this.formId);
  return tables[tableId];
}


