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
from ..Help import Help
import html
import time
import logging

"""
  TODO : je crois qu'on ne peut pas donner la clé publique (drop down list qui ne fonctionne pas)
"""

@register_web_module('/client/oauth/admin')
class OAuthClientAdmin(BaseHandler):
  
  @register_url(url='modifyclient', method='GET')
  def display(self):
    
    """
    Ajout/modification d'un client OIDC
    
    Versions
      12/02/2021 - 27/02/2021 - 28/12/2021 (mpham) : version initiale
      13/04/2021 (mpham)
      23/12/2022 (mpham) : méthode d'authentification à l'endpoint token
    """
    
    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id:
      rp = self.conf['oauth_clients'][rp_id]
    
    redirect_uri = rp.get('redirect_uri', '')

    self.send_template('OAuthClientAdmin.html',
      rp_id = rp_id,
      name = rp.get('name', ''),
      redirect_uri = redirect_uri,
      endpoint_configuration = rp.get('endpoint_configuration', 'Local configuration'),
      authorization_endpoint = rp.get('authorization_endpoint', ''),
      token_endpoint = rp.get('token_endpoint', ''),
      introspection_endpoint = rp.get('introspection_endpoint', ''),
      discovery_uri = rp.get('discovery_uri', ''),
      client_id = rp.get('client_id', ''),
      scope = rp.get('scope', ''),
      response_type = rp.get('response_type', 'code'),
      token_endpoint_auth_method = rp.get('token_endpoint_auth_method', 'POST'),
      introspect_at = Configuration.is_on(rp.get('introspect_at', 'off')),
      rs_client_id = rp.get('rs_client_id', ''),
      verify_certificates = Configuration.is_on(rp.get('verify_certificates', 'on')),
      )


  @register_url(url='modifyclient', method='POST')
  def modify(self):
  
    """
    Crée ou modifie un IdP dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    Versions
      01/11/2022 (mpham) : version initiale
      23/12/2022 (mpham) : méthode d'authentification à l'endpoint token
    """
    
    rp_id = self.post_form['rp_id']
    if rp_id == '':
      rp_id = self._generate_rpid(self.post_form['name'], self.conf['oauth_clients'].keys())
      self.conf['oauth_clients'][rp_id] = {}
    
    rp = self.conf['oauth_clients'][rp_id]
    
    for item in ['name', 'redirect_uri', 'endpoint_configuration', 'authorization_endpoint', 'token_endpoint', 'introspection_endpoint', 'discovery_uri', 
      'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'rs_client_id']:
      if self.post_form[item] == '':
        rp.pop(item, None)
      else:
        rp[item] = self.post_form[item]

    for secret in ['client_secret!', 'rs_client_secret!']:
      if self.post_form[secret] != '':
        rp[secret] = self.post_form[secret]

    for item in ['introspect_at', 'verify_certificates']:
      if item in self.post_form:
        rp[item] = 'on'
      else:
        rp[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection('/')


  @register_url(url='removeclient', method='GET')
  def remove(self):
  
    """
    Supprime un client OpenID Connect
    
    mpham 28/12/2021
    """

    rp_id = self.get_query_string_param('id')
    if rp_id is not None:
      self.conf['oauth_clients'].pop(rp_id, None)
      Configuration.write_configuration(self.conf)
      
    self.send_redirection('/')


  def _generate_rpid(self, name, existing_names):
    
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
