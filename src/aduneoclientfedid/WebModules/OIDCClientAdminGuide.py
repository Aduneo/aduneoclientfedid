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
from ..Configuration import Configuration
from ..Help import Help
from ..Template import Template
import html

"""
  TODO : je crois qu'on ne peut pas donner la clé publique (drop down list qui ne fonctionne pas)
"""

class OIDCClientAdminGuide(BaseHandler):
  
  def display(self):
    
    """
    Ajout/modification d'un client OIDC
    
    mpham 12/02/2021 - 27/02/2021 - 28/12/2021 - 13/04/2021
    """
    
    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id != '':
      rp = self.conf['oidc_clients'][rp_id]
    
    if 'redirect_uri' in rp:
      redirect_uri = rp['redirect_uri']
    else:
      redirect_uri = 'http'
      if Configuration.is_on(self.conf['server']['ssl']):
        redirect_uri = redirect_uri + 's'
      redirect_uri = redirect_uri + '://' + self.conf['server']['host']
      if (Configuration.is_on(self.conf['server']['ssl']) and self.conf['server']['port'] != '443') or (Configuration.is_off(self.conf['server']['ssl']) and self.conf['server']['port'] != '80'):
        redirect_uri = redirect_uri + ':' + self.conf['server']['port']
      redirect_uri = redirect_uri + '/oidc/client/callback'
    
    rp_name = rp.get('name', '')
    # méthode de configuration des endpoint
    list_option_endpoint_config = ''
    for value in ('Discovery URI', 'Local configuration'):
      selected = ''
      if value.casefold() == rp.get('endpoint_configuration', 'Discovery URI').casefold():
        selected = ' selected'
      list_option_endpoint_config += '<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>'

    # configuration des endpoint par discovery uri
    rp_discovery_uri = rp.get('discovery_uri', '')    
        
    # configuration de la cinématique
    client_id = html.escape(rp.get('client_id', ''))
    client_secret = html.escape(rp.get('client_secret!', ''))

    scope = html.escape(rp.get('scope', 'openid profile'))

    list_reponse_type = ''
    for value in ['code']:
      selected = ''
      if value == rp.get('response_type', ''):
        selected = ' selected'
      list_reponse_type += '<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>'
    
    
    checked = ''
    if Configuration.is_on(rp.get('fetch_userinfo', 'off')):
      checked = ' checked'

    self.send_template(
      'guide.htm', 
      rp_id=rp_id,
      rp_name=rp_name,
      redirect_uri=redirect_uri,
      list_option_endpoint_config=list_option_endpoint_config,
      rp_discovery_uri=rp_discovery_uri,
      client_id=client_id,
      client_secret=client_secret,
      scope=scope,
      list_reponse_type=list_reponse_type,
      checked=checked
      )


  def modify(self):
  
    """
    Crée ou modifie un IdP dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    """
    
    rp_id = self.post_form['rp_id']
    if rp_id == '':
      rp_id = self.generate_rpid(self.post_form['name'], self.conf['oidc_clients'].keys())
      self.conf['oidc_clients'][rp_id] = {}
    
    rp = self.conf['oidc_clients'][rp_id]
    
    for item in ['name', 'endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key', 
    'client_id', 'client_secret!', 'scope', 'response_type']:
      if self.post_form[item] == '':
        rp.pop(item, None)
      else:
        rp[item] = self.post_form[item]
      
    if 'fetch_userinfo' in self.post_form:
      rp['fetch_userinfo'] = 'on'
    else:
      rp['fetch_userinfo'] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection('/')


  def remove(self):
  
    """
    Supprime un client OpenID Connect
    
    mpham 28/12/2021
    """

    rp_id = self.get_query_string_param('id')
    if rp_id is not None:
      self.conf['oidc_clients'].pop(rp_id, None)
      Configuration.write_configuration(self.conf)
      
    self.send_redirection('/')


  def generate_rpid(self, name, existing_names):
    
    """
    Génère un identifiant à partir d'un nom
    en ne retenant que les lettres et les chiffres
    et en vérifiant que l'identifiant n'existe pas déjà
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    """
    
    base = name
    ok = False
    rank = 0
    
    while not ok:
      id = ''.join(c for c in base.casefold() if c.isalnum())
      if id == '':
        id = 'oidc_rp'
      if rank > 0:
        id = id+str(rank)
      
      if id in existing_names:
        rank = rank+1
      else:
        ok = True
        
    return id