"""
Copyright 2023 Aduneo

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url
from ..Configuration import Configuration
import html
import requests
import traceback
import uuid


@register_web_module('/client/oidc/logout')
class OIDCClientLogout(BaseHandler):
  """ OpenID Connect RP-Initiated Logout 1.0
  
  """
 
  @register_url(url='preparerequest', method='GET')
  def prepare_request(self):

    url_params = self.parse_query_string()

    oidc_id = self.get_query_string_param('id')
    
    if oidc_id is None:
      raise AduneoError("Client identifier not found in query string")
    
    if oidc_id not in self.conf['oidc_clients']:
      raise AduneoError("Client identifier not found in configuration")

    oidc_idp = self.conf['oidc_clients'][oidc_id]
    
    # Récupération du jeton d'identité (token ID)
    id_token = self.get_session_value('session_oidc_client_'+oidc_id)
    id_token = '' if id_token is None else id_token

    # Récupération des métadonnées (end_session_endpoint)
    if oidc_idp.get('endpoint_configuration', 'Local configuration').casefold() == 'discovery uri':
      self.add_content('<span id="meta_data_ph">Retrieving metadata from<br>'+oidc_idp['discovery_uri']+'<br>...</span>')
      try:
        self.log_info('Starting metadata retrieval')
        self.log_info('discovery_uri: '+oidc_idp['discovery_uri'])
        r = requests.get(oidc_idp['discovery_uri'], verify=False)
        self.log_info(r.text)
        meta_data = r.json()
        self.add_content('<script>document.getElementById("meta_data_ph").style.display = "none"</script>')
        meta_data['signature_key'] = oidc_idp.get('signature_key', '')
      except Exception as error:
        self.log_error(traceback.format_exc())
        self.add_content('failed<br>'+str(error))
        self.send_page()
        return
      if r.status_code != 200:
        self.log_error('Server responded with code '+str(r.status_code))
        self.add_content('failed<br>Server responded with code '+str(r.status_code))
        self.send_page()
        return
    else:
      meta_data = {}
      meta_data = dict((k, oidc_idp[k]) for k in ['end_session_endpoint'] if k in oidc_idp)

    self.add_content("<h1>OIDC IdP: "+oidc_idp["name"]+"</h1>")

    # Génération de l'URL de retour (post_logout_redirect_uri, optionnelle)
    #   Elle peut être donnée manuellement dans le fichier de configuration
    if 'post_logout_redirect_uri' in oidc_idp:
      post_logout_redirect_uri = oidc_idp['post_logout_redirect_uri']
    else:
      post_logout_redirect_uri = 'http'
      if Configuration.is_on(self.conf['server']['ssl']):
        post_logout_redirect_uri = post_logout_redirect_uri + 's'
      post_logout_redirect_uri = post_logout_redirect_uri + '://' + self.conf['server']['host']
      if (Configuration.is_on(self.conf['server']['ssl']) and self.conf['server']['port'] != '443') or (Configuration.is_off(self.conf['server']['ssl']) and self.conf['server']['port'] != '80'):
        post_logout_redirect_uri = post_logout_redirect_uri + ':' + self.conf['server']['port']
      post_logout_redirect_uri = post_logout_redirect_uri + '/oidc/client/logoutcallback'

    state = str(uuid.uuid4())
    
    self.add_content('<form name="request" action="sendrequest" method="post">')
    self.add_content('<input name="oidc_id" value="'+html.escape(oidc_id)+'" type="hidden" />')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>End session endpoint</td><td><input name="end_session_endpoint" value="'+html.escape(meta_data['end_session_endpoint'])+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>ID Token</td><td><input name="id_token_hint" value="'+html.escape(id_token)+'"class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>Post logout redirect URI</td><td><input name="post_logout_redirect_uri" value="'+html.escape(post_logout_redirect_uri)+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>State</td><td>'+html.escape(state)+'"</td></tr>')
    self.add_content('</table>')
    
    self.add_content('<td><input name="state" value="'+html.escape(state)+'" type="hidden"></td></tr>')
    self.add_content('<input name="logout_request" type="hidden">')
    self.add_content('<div style="padding-top: 20px; padding-bottom: 12px;"><div style="padding-bottom: 6px;"><strong>Logout request</strong> <img title="Copy request" class="smallButton" src="/images/copy.png" onClick="copyRequest()"/></div>')
    self.add_content('<span id="logout_request" style="font-size: 14px;"></span></div>')
    
    self.add_content('<button type="submit" class="button">Send to IdP</button>')
    self.add_content('</form>')

    self.add_content("""
    <script>
    function updateLogoutRequest() {
      var request = document.request.end_session_endpoint.value
        + '?id_token_hint='+encodeURIComponent(document.request.id_token_hint.value);
      ['post_logout_redirect_uri', 'state'].forEach(function(item, index) {
        if (document.request[item].value != '') { request += '&'+item+'='+encodeURIComponent(document.request[item].value); }
      });
      
      document.getElementById('logout_request').innerHTML = request;
      document.request.logout_request.value = request;
    }
    var input = document.request.getElementsByTagName('input');
    Array.prototype.slice.call(input).forEach(function(item, index) {
      if (item.type == 'text') { item.addEventListener("input", updateLogoutRequest); }
    });
    var select = document.request.getElementsByTagName('select');
    Array.prototype.slice.call(select).forEach(function(item, index) {
      if (item.name != 'signature_key_configuration') {
        item.addEventListener("change", updateLogoutRequest);
      }
    });
    updateLogoutRequest();

    function copyRequest() {
      copyTextToClipboard(document.request.logout_request.value);
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
    </script>
    """)
    
    self.send_page()


  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    
    """
    Récupère les informations saisies dans /oidc/preparelogoutrequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oidc/preparelogoutrequest et placée dans le paramètre logout_request
    
    mpham 01/03/2021
    """

    self.log_info('Redirection to IdP requested for logout')
    
    id_token_hint = self.post_form['id_token_hint']
    if id_token_hint == '':
      raise AduneoError('ID Token mandatory for logout')

    state = self.post_form['state']
    self.set_session_value(state, self.post_form['oidc_id'])
    
    logout_request = self.post_form['logout_request']
    self.log_info('Redirecting to:')
    self.log_info(logout_request)
    self.send_redirection(logout_request)


  @register_url(url='callback', method='GET')
  def callback(self):
  
    state = self.get_query_string_param('state')
    oidc_id = self.get_session_value(state)
    if oidc_id is not None:
      self.logoff('oidc_client_'+oidc_id)
  
    self.log_info('Logout callback')
    self.add_content('<h2>Logout callback</h2>')
    self.add_content('User successfully logged out')
    self.send_page()
  