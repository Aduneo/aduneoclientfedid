function help(imgElement, itemId) {
  // Il faut changer la manière d'identifier la page, car depuis que les utilisateurs peuvent configurer l'URL de retour OIDC, on ne peut plus se baser sur l'URL
  // Il faudrait plutôt mettre un data-help-root dans le <form> et remonter le DOM
  console.log(window.location.pathname.substring(1).replaceAll('/', '_')+'_'+itemId)
  var rect = imgElement.getBoundingClientRect();
  displayHelpPopup(rect.left+50, rect.top, window.location.pathname.substring(1).replaceAll('/', '_')+'_'+itemId)
}


function displayHelpPopup(x, y, helpId) {
  
  document.getElementById("helpHeader").innerHTML = 'Loading...';
  document.getElementById("helpContent").innerHTML = 'Loading...';
  
  var xhttp = new XMLHttpRequest();
  xhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
      jsonResponse = JSON.parse(xhttp.responseText);
      document.getElementById("helpHeader").innerHTML = jsonResponse.header;
      document.getElementById("helpContent").innerHTML = jsonResponse.content;
    }
  };
  xhttp.open("GET", "/help?id="+helpId, true);
  xhttp.send();
  
  openDrag('helpWindow', x, window.pageYOffset+y)
}

// draggable windows

function openDrag(elId, x, y) {
  dragWindow = document.getElementById(elId);
  dragWindow.style.left = x;
  dragWindow.style.top = y;
  dragWindow.style.visibility = 'visible';
}

function closeDrag(el) {
  el.parentNode.parentNode.style.visibility = 'hidden'
}

function startDrag(el, ev) {
  el.orgMouseX = ev.screenX;
  el.orgMouseY = ev.screenY;
  el.orgWindowX = el.offsetLeft;
  el.orgWindowY = el.offsetTop;
  el.onmousemove = drag;
  el.onmouseup = stopDrag;
  return false
}

	function drag(e) {
	  newX = this.orgWindowX + e.screenX - this.orgMouseX;
	  newY = this.orgWindowY + e.screenY - this.orgMouseY;
	  this.style.left = newX + 'px'
	  this.style.top = newY + 'px'
  return false
	}


function stopDrag() {
  this.onmousemove = null;
  this.onmouseup = null;
  return false
}

function showHelp(num) {
  var d = document.getElementById("un");
  d.className = "fixed etapes";
  d.hidden = true;
  var d = document.getElementById("unTab");
  d.className = "fixed";

  var d = document.getElementById("deux");
  d.className = "fixed etapes";
  d.hidden = true;
  var d = document.getElementById("deuxTab");
  d.className = "fixed";

  var d = document.getElementById("trois");
  d.className = "fixed etapes";
  d.hidden = true;
  var d = document.getElementById("troisTab");
  d.className = "fixed";

  var d = document.getElementById("quatre");
  d.className = "fixed etapes";
  d.hidden = true;
  var d = document.getElementById("quatreTab");
  d.className = "fixed";

  if (num != "zero") {
    var d = document.getElementById(num);
    d.className = d.className + " etape_" + num;
    d.hidden = false;
    window.scrollTo({top: d.getBoundingClientRect().y, left: 0, behavior: 'smooth'});
    var d = document.getElementById(num+"Tab");
    d.className = d.className + " etape_" + num;
  }
}

async function includeHtml(name) {
  const idp = ["okta", "keycloak", "azuread"]

  if (idp.includes(name)){
    var oReqUn = new XMLHttpRequest();
    oReqUn.open("get", "https://localhost/html/"+name+"Un.html", true);
    oReqUn.send();
    var oReqDeux = new XMLHttpRequest();
    oReqDeux.open("get", "https://localhost/html/"+name+"Deux.html", true);
    oReqDeux.send();
    var oReqTrois = new XMLHttpRequest();
    oReqTrois.open("get", "https://localhost/html/"+name+"Trois.html", true);
    oReqTrois.send();

    await new Promise(resolve => setTimeout(resolve, 1000));

    var un = document.getElementById("includeUn");
    var deux = document.getElementById("includeDeux");
    var trois = document.getElementById("includeTrois");
    un.innerHTML = oReqUn.responseText;
    deux.innerHTML = oReqDeux.responseText;
    trois.innerHTML = oReqTrois.responseText;
  } else if (name === "any") {
    var un = document.getElementById("includeUn");
    var deux = document.getElementById("includeDeux");
    var trois = document.getElementById("includeTrois");
    un.innerHTML = "";
    deux.innerHTML = "";
    trois.innerHTML = "";
  } else{
    throw "Mauvais argument: " + name;
  }
}
