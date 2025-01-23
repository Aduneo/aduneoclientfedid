/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
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
