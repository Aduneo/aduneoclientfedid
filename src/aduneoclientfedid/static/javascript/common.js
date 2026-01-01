/**
 * @license
 * Copyright 2023-2026 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function openConsole(force=false) {
  if (autoOpenWebconsole || force) {
    webConsole = window.open("/webconsole", "console", "popup,height=500,width=800");
  }
}

var log_last_line = -1
function update_logs(){
  //var req = new XMLHttpRequest();
  //req.open("get", "https://localhost/webconsole/buffer?logLastLine="+log_last_line, false);
  //req.send();

  fetch("/webconsole/buffer?logLastLine="+log_last_line)
  .then(function(response) {
    return response.json();
  })
  .then(function(jsonResponse) {
    if (jsonResponse.result == 'ok') {
      logs = document.getElementById("logs");
      incr_pos = log_last_line+1 - jsonResponse.incr_first_line
      if (incr_pos >= 0) {
        for (i=incr_pos ; i<jsonResponse.incr.length ; i++) {
          logs.innerHTML = logs.innerHTML + jsonResponse.incr[i]+'<br>';
        }
      }
      highlight_word(document.getElementById("highlight").value);
      log_last_line = jsonResponse.log_last_line;
    }
  });

}


function clear_webconsole() {
  fetch('/webconsole/buffer', {
    method:'PUT'
  }).then(response => {
    return response.json()
  }).then(data => {
    log_last_line = -1
    logs = document.getElementById("logs");
    logs.innerHTML = '';
  });
}


function highlight_word(word) {
  if (word){
    //console.log(word)
    logs.innerHTML =  logs.innerHTML.replaceAll("<mark>", "");
    logs.innerHTML =  logs.innerHTML.replaceAll("</mark>", "");
    logs = document.getElementById("logs");
    logs.innerHTML =  logs.innerHTML.replaceAll(word, "<mark>" + word + "</mark>")  //replaceAll(logs.innerHTML, word, "<mark>" + word + "</mark>");

    "".replace
  }
}

//https://stackoverflow.com/questions/1144783/how-to-replace-all-occurrences-of-a-string-in-javascript
function repla(str, find, replace) {
  return str.replace(new RegExp(find, 'g'), replace);
}

function copyTextToClipboard(text) {
  var tempArea = document.createElement('textarea')
  tempArea.value = text
  document.body.appendChild(tempArea)
  tempArea.select()
  tempArea.setSelectionRange(0, 99999)
  document.execCommand("copy")
  document.body.removeChild(tempArea)
}


function expandSection(sectionId) {
  section = document.getElementById(sectionId);
  content = section.getElementsByClassName("section_content")[0]
  content.style.display = 'block'
  plus_button = section.getElementsByClassName("plus_button")[0]
  plus_button.style.display = 'none'
  minus_button = section.getElementsByClassName("minus_button")[0]
  minus_button.style.display = 'block'
}

function collapseSection(sectionId) {
  section = document.getElementById(sectionId);
  content = section.getElementsByClassName("section_content")[0]
  content.style.display = 'none'
  plus_button = section.getElementsByClassName("plus_button")[0]
  plus_button.style.display = 'block'
  minus_button = section.getElementsByClassName("minus_button")[0]
  minus_button.style.display = 'none'
}


// ================ boutons et menus ================

function display_middle_menu(a_item) {
  
  var menu = [];
  for (let menu_item of a_item.dataset.menu.split('\1')) {
    let menu_items = menu_item.split('\2');
    menu[menu_items[0]] = menu_items[1];
  }

  var menuEls = [];
  
  // création du masque interdisant de cliquer    
  const overlayEl = document.createElement('div');
  overlayEl.style.position = 'fixed';
  overlayEl.style.inset = 0;
  let textEl = document.createTextNode('');
  overlayEl.appendChild(textEl);
  overlayEl.onclick = () => { overlayEl.remove(); maskEl.remove(); for (menuEl of menuEls) { menuEl.remove(); } }
  document.body.appendChild(overlayEl);

  let yPos = a_item.getBoundingClientRect().bottom;
  
  const maskEl = document.createElement('div');
  maskEl.style.position = 'fixed';
  maskEl.style.top = yPos;
  maskEl.style.left = a_item.getBoundingClientRect().left;
  maskEl.style.backgroundColor = 'white';
  textEl = document.createTextNode('');
  maskEl.appendChild(textEl);
  document.body.appendChild(maskEl);
  
  let maxWidth = -1;
  for (label in menu) {
  
    console.log(label, menu[label])
  
    let menuEl = document.createElement('span');
    menuEl.className = "middlebutton";
    menuEl.style.position = 'fixed';
    menuEl.style.top = yPos;
    menuEl.style.left = a_item.getBoundingClientRect().left;
    menuEl.style.textAlign = 'left';
    menuEl.style.userSelect = 'none';
    menuEl.dataset.page = menu[label];
    let labelEl = document.createTextNode(label);
    menuEl.appendChild(labelEl);
    menuEl.onclick = (ev) => { overlayEl.remove(); maskEl.remove(); for (menuEl of menuEls) { menuEl.remove(); } window.location.href = ev.target.dataset.page; }
    document.body.appendChild(menuEl);
    
    menuEls.push(menuEl);
    
    yPos = menuEl.getBoundingClientRect().bottom;
    width = menuEl.getBoundingClientRect().right - menuEl.getBoundingClientRect().left
    console.log(menuEl.getBoundingClientRect().width)
    console.log(menuEl.style.padding)
    if (width > maxWidth) maxWidth = width;
  }
  
  maskEl.style.width = maxWidth+34;  // 34 correspond à margin + padding de middlebutton, je ne sais pas encore comment l'avoir directement
  maskEl.style.height = yPos - a_item.getBoundingClientRect().bottom;
  for (menuEl of menuEls) {
    menuEl.style.width = maxWidth;
  }
  
  
}

function test() {
  console.log("BUU");
}
