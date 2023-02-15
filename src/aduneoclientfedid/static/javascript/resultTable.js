function showLong(colId) {
  document.getElementById(colId+'s').style.display = 'none'
  document.getElementById(colId+'l').style.display = 'inline'
}
function showShort(colId) {
  document.getElementById(colId+'l').style.display = 'none'
  document.getElementById(colId+'s').style.display = 'inline'
}
function copyValue(colId) {
  item = document.getElementById(colId+'c')
  copyTextToClipboard(item.innerHTML.replaceAll('&nbsp;', ' ').replaceAll('<br>', "\\n"))
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
