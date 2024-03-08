/**
 * @license
 * Copyright 2023 Aduneo
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
