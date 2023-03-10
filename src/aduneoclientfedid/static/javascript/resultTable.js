/**
 * @license
 * Copyright 2023 Aduneo
 * SPDX-License-Identifier: Apache-2.0
 */
function showLong(colId) {
  document.getElementById(colId+'s').style.display = 'none'
  document.getElementById(colId+'l').style.display = 'inline'
  document.getElementById(colId+'_expand').style.display = 'none'
  document.getElementById(colId+'_collapse').style.display = 'inline'
}
function showShort(colId) {
  document.getElementById(colId+'s').style.display = 'inline'
  document.getElementById(colId+'l').style.display = 'none'
  document.getElementById(colId+'_expand').style.display = 'inline'
  document.getElementById(colId+'_collapse').style.display = 'none'
}
function copyValue(colId) {
  item = document.getElementById(colId+'_raw')
  //copyTextToClipboard(item.innerHTML.replaceAll('&nbsp;', ' ').replaceAll('<br>', "\\n"))
  copyTextToClipboard(item.innerHTML)
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
