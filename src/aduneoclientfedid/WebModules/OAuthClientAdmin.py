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
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import CfiForm
from ..Configuration import Configuration
from ..Help import Help
import html
import time
import logging

"""
  TODO : je crois qu'on ne peut pas donner la clé publique (drop down list qui ne fonctionne pas)
"""

@register_web_module('/client/oauth2/admin')
class OAuthClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=True)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application : modify_single
        - modification différencée IdP et les différents clients qu'il gère       : modify_multi
        
    Versions:
      23/08/2024 (mpham) version initiale copiée de OIDC
    """

    idp = {}

    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création
      self.modify_single_display()
    else:
      # Modification
      idp = self.conf['idps'].get(idp_id)
      if not idp:
        raise AduneoError(f"IdP {idp_id} not found in configuration")
        
      oidc_clients = idp.get('oidc_clients', {})  
      oauth2_clients = idp.get('oauth2_clients', {})  
      saml_clients = idp.get('saml_clients', {})  
        
      if len(oidc_clients) == 0 and len(oauth2_clients) == 1 and len(saml_clients) == 0:
        self.modify_single_display()
      else:
        self.modify_multi_display()
      

  def modify_single_display(self):
    """ Modification d'un client OAuth 2 dans le mode single (ie IdP avec un uniquement un client OAuth)
    
    Affiche le formulaire avec les paramètres
    
    Appelé par modify_client_router
    
    Versions:
      23/08/2024 (mpham) version initiale copiée de OIDC
    """

    idp_params = {}
    app_params = {}

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {'oidc': {}}, 'oauth2_clients': {'client': {}}}
    if idp_id != '' and app_id != '':
      idp = self.conf['idps'][idp_id]
      idp_params = idp['idp_parameters']['oauth2']
      app_params = idp['oauth2_clients'][app_id]

    form_content = {
      'idp_id': idp_id,
      'app_id': app_id,
      'name': idp.get('name', ''),
      'endpoint_configuration': idp_params.get('endpoint_configuration', 'Authorization Server Metadata URI'),
      'metadata_uri': idp_params.get('metadata_uri', ''),
      'authorization_endpoint': idp_params.get('', ''),
      'token_endpoint': idp_params.get('', ''),
      'introspection_endpoint': idp_params.get('introspection_endpoint', ''),
      'introspection_method': idp_params.get('introspection_method', 'get'),
      'revocation_endpoint': idp_params.get('revocation_endpoint', ''),
      'issuer': idp_params.get('issuer', ''),
      'signature_key_configuration': idp_params.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': idp_params.get('jwks_uri', ''),
      'signature_key': idp_params.get('signature_key', ''),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', ''),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
      'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('oauth2adminsingle', form_content, action='modifyclientsingle', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('as_endpoints', title="Authorization Server Endpoints") \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'Authorization Server Metadata URI': 'Authorization Server Metadata URI', 'Local configuration': 'Local configuration'},
          default = 'Authorization Server Metadata URI'
          ) \
        .text('metadata_uri', label='AS Metadata URI', clipboard_category='metadata_uri', displayed_when="@[endpoint_configuration] = 'Authorization Server Metadata URI'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .closed_list('introspection_method', label='Introspect. Request Method',
          values = {'get': 'GET', 'post': 'POST'},
          default = 'get'
          ) \
        .text('revocation_endpoint', label='Revocation endpoint', clipboard_category='revocation_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
      .end_section() \
      .start_section('client_endpoints', title="Client Endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/login/callback'); }" 
          ) \
      .end_section() \
      .start_section('oauth2_configuration', title="OAuth 2 Configuration") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('response_type', label='Reponse Type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth method', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OAuth 2 Authorization'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', self.conf.is_on('/preferences/clipboard/remember_secrets', False))

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    self.send_page()


  @register_url(url='modifyclientsingle', method='POST')
  def modify_single_modify(self):
    """ Crée ou modifie un IdP + App OIDC (mode single) dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      23/08/2024 (mpham) version initiale copiée d'OIDC
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_idpid(self.post_form['name'], self.conf['idps'].keys())
      app_id = 'client'
      self.conf['idps'][idp_id] = {'idp_parameters': {'oauth2': {}}, 'oauth2_clients': {'client': {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']['oidc']
    app_params = idp['oauth2_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name']
    app_params['name'] = 'OAuth2 Client'
    
    for item in ['endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'revocation_endpoint', 'introspection_endpoint', 'introspection_method', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
      if self.post_form.get(item, '') == '':
        idp_params.pop(item, None)
      else:
        idp_params[item] = self.post_form[item]
      
    for item in ['redirect_uri', 'client_id', 'scope', 'response_type', 'token_endpoint_auth_method']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item]
      
    for secret in ['client_secret']:
      if self.post_form.get(secret, '') != '':
        app_params[secret+'!'] = self.post_form[secret]
        
    for item in ['verify_certificates']:
      if item in self.post_form:
        idp_params[item] = 'on'
      else:
        idp_params[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}")










  
  @register_url(url='modifyclient_old', method='GET')
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
    
    if self.post_form['name'] == '':
      self.post_form['name'] = rp_id
    
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
        id = 'oauth_rp'
      if rank > 0:
        id = id+str(rank)
      
      if id in existing_names:
        rank = rank+1
      else:
        ok = True
        
    return id
