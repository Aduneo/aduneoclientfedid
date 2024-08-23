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
import html


@register_web_module('/client/oidc/admin')
class OIDCClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=True)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application : modify_single
        - modification différencée IdP et les différents clients qu'il gère       : modify_multi
        
    Versions:
      10/08/2024 (mpham) version initiale
      23/08/2024 (mpham) request parameters
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
      oauth2_clients = idp.get('oidc_oauth2', {})  
      saml_clients = idp.get('saml_clients', {})  
        
      if len(oidc_clients) == 1 and len(oauth2_clients) == 0 and len(saml_clients) == 0:
        self.modify_single_display()
      else:
        self.modify_multi_display()
      

  def modify_single_display(self):

    idp_params = {}
    app_params = {}

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {'oidc': {}}, 'oidc_clients': {'client': {}}}
    if idp_id != '' and app_id != '':
      idp = self.conf['idps'][idp_id]
      idp_params = idp['idp_parameters']['oidc']
      app_params = idp['oidc_clients'][app_id]

    form_content = {
      'idp_id': idp_id,
      'app_id': app_id,
      'name': idp.get('name', ''),
      'endpoint_configuration': idp_params.get('endpoint_configuration', 'Discovery URI'),
      'discovery_uri': idp_params.get('discovery_uri', ''),
      'authorization_endpoint': idp_params.get('', ''),
      'token_endpoint': idp_params.get('', ''),
      'userinfo_endpoint': idp_params.get('userinfo_endpoint', ''),
      'userinfo_method': idp_params.get('userinfo_method', 'get'),
      'logout_endpoint': idp_params.get('logout_endpoint', ''),
      'issuer': idp_params.get('issuer', ''),
      'signature_key_configuration': idp_params.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': idp_params.get('jwks_uri', ''),
      'signature_key': idp_params.get('signature_key', ''),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'post_logout_redirect_uri': app_params.get('post_logout_redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', 'openid'),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
      'display': app_params.get('display', ''),
      'prompt': app_params.get('prompt', ''),
      'max_age': app_params.get('max_age', ''),
      'ui_locales': app_params.get('ui_locales', ''),
      'id_token_hint': app_params.get('id_token_hint', ''),
      'login_hint': app_params.get('login_hint', ''),
      'acr_values': app_params.get('acr_values', ''),
      'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('oidcadminsingle', form_content, action='modifyclientsingle', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('op_endpoints', title="OP endpoints") \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'Discovery URI': 'Discovery URI', 'Local configuration': 'Local configuration'},
          default = 'Discovery URI'
          ) \
        .text('discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[endpoint_configuration] = 'Discovery URI'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .closed_list('userinfo_method', label='Userinfo Request Method',
          values = {'get': 'GET', 'post': 'POST'},
          default = 'get'
          ) \
      .end_section() \
      .start_section('id_token_validation', title="ID token validation", displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('issuer', label='Issuer', clipboard_category='issuer', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .closed_list('signature_key_configuration', label='Signature key configuration', displayed_when="@[endpoint_configuration] = 'Local configuration'",
          values = {'JWKS URI': 'JWKS URI', 'Local configuration': 'Local configuration'},
          default = 'jWKS URI'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[endpoint_configuration] = 'Local configuration' and @[signature_key_configuration] = 'JWKS URI'") \
        .text('signature_key', label='Signature key', displayed_when="@[endpoint_configuration] = 'Local configuration' and @[signature_key_configuration] = 'Local configuration'") \
      .end_section() \
      .start_section('rp_endpoints', title="RP endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/login/callback'); }" 
          ) \
        .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/logout/callback'); }" \
          ) \
      .end_section() \
      .start_section('openid_connect_configuration', title="OpenID Connect Configuration") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('response_type', label='Reponse type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth method', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() \
      .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=False) \
        .closed_list('display', label='Display', 
          values={'': '', 'page': 'page', 'popup': 'popup', 'touch': 'touch', 'wap': 'wap'},
          default = ''
          ) \
        .closed_list('prompt', label='Prompt', 
          values={'': '', 'none': 'none', 'login': 'login', 'consent': 'consent', 'select_account': 'select_account'},
          default = ''
          ) \
        .text('max_age', label='Max Age', clipboard_category='max_age') \
        .text('ui_locales', label='UI Locales', clipboard_category='ui_locales') \
        .text('id_token_hint', label='ID Token Hint', clipboard_category='id_token_hint') \
        .text('login_hint', label='Login Hint', clipboard_category='login_hint') \
        .text('acr_values', label='ACR Values', clipboard_category='acr_values') \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', self.conf.is_on('/preferences/clipboard/remember_secrets', False))

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    self.send_page()


  @register_url(url='modifyclientsingle', method='POST')
  def modify_single_modify(self):
    """ Crée ou modifie un IdP + App OIDC (mode single) dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      28/02/2021 (mpham)
      24/12/2021 (mpham) ajout de redirect_uri
      09/12/2022 (mpham) ajout de token_endpoint_auth_method
      22/02/2023 (mpham) suppression des références à fetch_userinfo puisque l'appel à userinfo est désormais manuel
      10/08/2024 (mpham) version 2 de la configuration
      23/08/2024 (mpham) request parameters
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_idpid(self.post_form['name'], self.conf['idps'].keys())
      app_id = 'client'
      self.conf['idps'][idp_id] = {'idp_parameters': {'oidc': {}}, 'oidc_clients': {'client': {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']['oidc']
    app_params = idp['oidc_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name']
    app_params['name'] = 'OIDC Client'
    
    for item in ['endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'userinfo_method', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
      if self.post_form.get(item, '') == '':
        idp_params.pop(item, None)
      else:
        idp_params[item] = self.post_form[item]
      
    for item in ['redirect_uri', 'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'post_logout_redirect_uri',
    'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values']:
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
    
    self.send_redirection(f"/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}")


  @register_url(url='removeclient', method='GET')
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


  def _generate_idpid(self, name, existing_names):
    
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
