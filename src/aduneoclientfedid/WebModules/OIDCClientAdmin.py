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

  @register_page_url(url='modifyclient', method='GET', template='page_default.html')
  def display(self):

    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id != '':
      rp = self.conf['oidc_clients'][rp_id]

    self.add_javascript_include('/javascript/oidc.js')

    form_content = {
      'rp_id': rp_id,
      'name': rp.get('name', ''),
      'endpoint_configuration': rp.get('endpoint_configuration', 'Discovery URI'),
      'discovery_uri': rp.get('discovery_uri', ''),
      'authorization_endpoint': rp.get('', ''),
      'token_endpoint': rp.get('', ''),
      'userinfo_endpoint': rp.get('userinfo_endpoint', ''),
      'logout_endpoint': rp.get('logout_endpoint', ''),
      'issuer': rp.get('issuer', ''),
      'signature_key_configuration': rp.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': rp.get('jwks_uri', ''),
      'signature_key': rp.get('signature_key', ''),
      'redirect_uri': rp.get('redirect_uri', ''),
      'post_logout_redirect_uri': rp.get('post_logout_redirect_uri', ''),
      'client_id': rp.get('client_id', ''),
      'scope': rp.get('scope', 'openid'),
      'response_type': rp.get('response_type', 'code'),
      'token_endpoint_auth_method': rp.get('token_endpoint_auth_method', 'client_secret_basic'),
      'verify_certificates': Configuration.is_on(rp.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('oidcadmin', form_content, submit_label='Save') \
      .hidden('rp_id') \
      .text('name', label='Name') \
      .start_section('op_endpoints', title="OP endpoints") \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'Discovery URI': 'Discovery URI', 'Local configuration': 'Local configuration'},
          default = 'Discovery URI'
          ) \
        .text('discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[endpoint_configuration] = 'Discovery URI'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
        .text('logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[endpoint_configuration] = 'Local configuration'") \
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
          on_load="init_url_with_domain({inputItem}, '/client/oidc/login/callback');"
          ) \
        .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri',
          on_load="init_url_with_domain({inputItem}, '/client/oidc/logout/callback');"
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
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', True)

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())


  @register_url(url='modifyclient', method='POST')
  def modify(self):
  
    """
    Crée ou modifie un IdP dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    mpham 24/12/2021 - ajout de redirect_uri
    mpham 09/12/2022 - ajout de token_endpoint_auth_method
    mpham 22/02/2023 - suppression des références à fetch_userinfo puisque l'appel à userinfo est désormais manuel
    """
    
    
    rp_id = self.post_form['rp_id']
    if rp_id == '':
      rp_id = self._generate_rpid(self.post_form['name'], self.conf['oidc_clients'].keys())
      self.conf['oidc_clients'][rp_id] = {}
    
    rp = self.conf['oidc_clients'][rp_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = rp_id
    
    for item in ['name', 'redirect_uri', 'endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key', 
    'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'post_logout_redirect_uri']:
      if self.post_form.get(item, '') == '':
        rp.pop(item, None)
      else:
        rp[item] = self.post_form[item]
      
    for secret in ['client_secret']:
      if self.post_form.get(secret, '') != '':
        rp[secret+'!'] = self.post_form[secret]
        
    for item in ['verify_certificates']:
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
      self.conf['oidc_clients'].pop(rp_id, None)
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
