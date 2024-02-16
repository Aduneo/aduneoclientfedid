function init_url_with_domain(inputItem, url_path) {
  if (inputItem.value == '') {
    inputItem.value = window.location.origin + url_path;
  }
}