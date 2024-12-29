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
from .OIDCClientAdmin import OIDCClientAdmin
from .OAuthClientAdmin import OAuthClientAdmin
import copy
import html
import uuid


@register_web_module('/client/idp/admin')
class IdPClientAdmin(BaseHandler):

  @register_page_url(url='modify', method='GET', template='page_default.html', continuous=True)
  def modify_display(self):
    """ Modification des paramètres de l'IdP
    
    Remarque : on peut aussi modifier ces paramètres dans les pages d'adminisration OIDC et OAuth si l'IdP n'a qu'un unique client
    
    TODO : ajouter SAML
    
    Versions:
      25/12/2024 (mpham) version initiale
    """


    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {'oidc': {}, 'oauth2': {}}}
    else:
      idp = copy.deepcopy(self.conf['idps'][idp_id])

    idp['id'] = idp_id
    form = self.get_idp_form(idp)  

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    self.send_page()


  @register_url(url='modify', method='POST')
  def modify_save(self):
    """ Crée ou modifie un IdP dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      25/12/2024 (mpham)
    """
    
    idp_id = self.post_form['idp_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_idpid(self.post_form['name'].strip(), self.conf['idps'].keys())
      self.conf['idps'][idp_id] = {'idp_parameters': {'oidc': {}, 'oauth2': {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    oidc_params = idp_params.get('oidc')
    if not oidc_params:
      idp['idp_parameters']['oidc'] = {}
      oidc_params = idp_params['oidc']
    oauth2_params = idp_params.get('oauth2')
    if not oauth2_params:
      idp_params['oauth2'] = {}
      oauth2_params = idp_params['oauth2']
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name'].strip()

    # Paramètres OIDC
    for item in ['endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'userinfo_method', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
      if self.post_form.get('oidc_'+item, '') == '':
        oidc_params.pop(item, None)
      else:
        oidc_params[item] = self.post_form['oidc_'+item].strip()
      
    # Paramètres OAuth 2
    for item in ['endpoint_configuration', 'metadata_uri', 'authorization_endpoint', 'token_endpoint', 
    'revocation_endpoint', 'introspection_endpoint', 'introspection_http_method', 'introspection_auth_method', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
      if self.post_form.get('oauth2_'+item, '') == '':
        oauth2_params.pop(item, None)
      else:
        oauth2_params[item] = self.post_form['oauth2_'+item].strip()
      
    # Paramètres communs
    for item in ['verify_certificates']:
      if item in self.post_form:
        idp_params[item] = 'on'
      else:
        idp_params[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/idp/admin/display?idpid={html.escape(idp_id)}")


  @register_page_url(url='display', method='GET', template='page_default.html', continuous=True)
  def display(self):
    """ Affichage des paramètres de l'IdP
    
    TODO : ajouter SAML
    
    Versions:
      25/12/2024 (mpham) version initiale
    """


    idp_id = self.get_query_string_param('idpid', '')
    idp = copy.deepcopy(self.conf['idps'][idp_id])
    
    idp['id'] = idp_id
    form = self.get_idp_form(idp)  

    self.add_html(form.get_html(display_only=True))

    # Bouton de modification de l'IdP
    self.add_html(f""" 
      <div>
        <span><a href="modify?idpid={idp_id}" class="smallbutton">Modify IdP parameters</a></span>
      </div>
    """)
    
    # Clients OIDC
    self.add_html(f""" 
      <h2>OpenID Connect clients</h2>
      <div>
        <span><a href="/client/oidc/admin/modifymulti?idpid={idp_id}" class="smallbutton">Add client</a></span>
      </div>
    """)
    
    for client_id in idp.get('oidc_clients', {}):
      client = idp['oidc_clients'][client_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oidc/admin/modifymulti?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
          <span><a href="/client/oidc/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Logout</a></span>
          <span><a href="/client/oidc/admin/modifymulti?idpid={idp_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(client.get('name', '')),
          idp_id = idp_id,
          app_id = client_id,
          div_id = param_uuid,
          ))
          
      client['idp_id'] = idp_id
      client['app_id'] = client_id
      client_form = OIDCClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = client_form.get_html(display_only=True),
          ))
    
    # Clients OAuth 2
    self.add_html(f""" 
      <h2>OAuth 2 clients</h2>
      <div>
        <span><a href="/client/oauth2/admin/modifymulti?idpid={idp_id}" class="smallbutton">Add client</a></span>
      </div>
    """)
    
    for client_id in idp.get('oauth2_clients', {}):
      client = idp['oauth2_clients'][client_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oauth2/admin/modifymulti?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
          <span><a href="/client/oauth2/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Logout</a></span>
          <span><a href="/client/oauth2/admin/removeclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(client.get('name', '')),
          idp_id = idp_id,
          app_id = client_id,
          div_id = param_uuid,
          ))
          
      client['idp_id'] = idp_id
      client['app_id'] = client_id
      client_form = OAuthClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = client_form.get_html(display_only=True),
          ))

    # API OAuth 2
    self.add_html(f""" 
      <h2>OAuth 2 API</h2>
      <div>
        <span><a href="/client/oauth2/admin/modifyapi?idpid={idp_id}" class="smallbutton">Add API</a></span>
      </div>
    """)
    
    for api_id in idp.get('oauth2_apis', {}):
      api = idp['oauth2_apis'][api_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oauth2/admin/modifyapi?idpid={idp_id}&apiid={api_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oauth2/admin/removeapi?idpid={idp_id}&apiid={api_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(api.get('name', '')),
          idp_id = idp_id,
          api_id = api_id,
          div_id = param_uuid,
          ))
          
      api['idp_id'] = idp_id
      api['api_id'] = api_id
      #client_form = OAuthClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = 'TEST',
          ))

    
    self.send_page()
    


  @register_url(url='remove', method='GET')
  def remove(self):
  
    """
    Supprime un IdP
    
    Versions:
      28/02/2021 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('id')
    if idp_id is not None:
      self.conf['idps'].pop(idp_id, None)
      Configuration.write_configuration(self.conf)
      
    self.send_redirection('/')


  def get_idp_form(handler, idp:dict):
    """ Retourne un RequesterForm avec un IdP
    
    TODO : ajouter SAML
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      idp: dict avec les paramètres de l'IdP, dans le formalisme du fichier de configuration
             Attention : il faut ajouter le champ id avec l'identifiant unique de l'IdP
             
    Returns:
      objet RequesterForm
    
    Versions:
      25/12/2024 (mpham) version initiale
    """

    idp_params = idp['idp_parameters']
    oidc_params = idp_params.get('oidc', {})
    oauth2_params = idp_params.get('oauth2', {})

    form_content = {
      'idp_id': idp.get('id', ''),
      'name': idp.get('name', ''),
      'oidc_endpoint_configuration': oidc_params.get('endpoint_configuration', 'discovery_uri'),
      'oidc_discovery_uri': oidc_params.get('discovery_uri', ''),
      'oidc_authorization_endpoint': oidc_params.get('', ''),
      'oidc_token_endpoint': oidc_params.get('', ''),
      'oidc_userinfo_endpoint': oidc_params.get('userinfo_endpoint', ''),
      'oidc_userinfo_method': oidc_params.get('userinfo_method', 'get'),
      'oidc_logout_endpoint': oidc_params.get('logout_endpoint', ''),
      'oidc_issuer': oidc_params.get('issuer', ''),
      'oidc_signature_key_configuration': oidc_params.get('signature_key_configuration', 'discovery_uri'),
      'oidc_jwks_uri': oidc_params.get('jwks_uri', ''),
      'oidc_signature_key': oidc_params.get('signature_key', ''),
      'oauth2_endpoint_configuration': oauth2_params.get('endpoint_configuration', 'metadata_uri'),
      'oauth2_metadata_uri': oauth2_params.get('metadata_uri', ''),
      'oauth2_authorization_endpoint': oauth2_params.get('', ''),
      'oauth2_token_endpoint': oauth2_params.get('', ''),
      'oauth2_introspection_endpoint': oauth2_params.get('introspection_endpoint', ''),
      'oauth2_introspection_http_method': oauth2_params.get('introspection_http_method', 'get'),
      'oauth2_introspection_auth_method': oauth2_params.get('introspection_auth_method', 'basic'),
      'oauth2_revocation_endpoint': oauth2_params.get('revocation_endpoint', ''),
      'oauth2_signature_key_configuration': oauth2_params.get('signature_key_configuration', 'jwks_uri'),
      'oauth2_jwks_uri': oauth2_params.get('jwks_uri', ''),
      'oauth2_signature_key': oauth2_params.get('signature_key', ''),
      'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('idpadmin', form_content, action='modify', submit_label='Save') \
      .hidden('idp_id') \
      .text('name', label='Name') \
      .start_section('oidc_configuration', title="OIDC configuration", collapsible=True) \
        .start_section('op_endpoints', title="OP endpoints") \
          .closed_list('oidc_endpoint_configuration', label='Endpoint configuration', 
            values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
            default = 'discovery_uri'
            ) \
          .text('oidc_discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[oidc_endpoint_configuration] = 'discovery_uri'") \
          .text('oidc_authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oidc_userinfo_method', label='Userinfo Request Method',
            values = {'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
        .end_section() \
        .start_section('id_token_validation', title="ID token validation") \
          .text('oidc_issuer', label='Issuer', clipboard_category='issuer', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oidc_signature_key_configuration', label='Signature key configuration',
            values = {'discovery_uri': 'JWKS from discovery URI', 'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
            default = 'discovery_uri'
            ) \
          .text('oidc_jwks_uri', label='JWKS URI', displayed_when="@[oidc_signature_key_configuration] = 'jwks_uri'") \
          .text('oidc_signature_key', label='Signature key', displayed_when="@[oidc_signature_key_configuration] = 'local_configuration'") \
        .end_section() \
      .end_section() \
      .start_section('oauth2_configuration', title="OAuth 2 configuration", collapsible=True) \
        .start_section('as_endpoints', title="Authorization Server Endpoints") \
          .closed_list('oauth2_endpoint_configuration', label='Endpoint configuration', 
            values={'metadata_uri': 'Authorization Server Metadata URI', 'local_configuration': 'Local configuration'},
            default = 'metadata_uri'
            ) \
          .text('oauth2_metadata_uri', label='AS Metadata URI', clipboard_category='metadata_uri', displayed_when="@[oauth2_endpoint_configuration] = 'metadata_uri'") \
          .text('oauth2_authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .text('oauth2_token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .text('oauth2_introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oauth2_introspection_http_method', label='Introspect. Request Method',
            values = {'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
          .closed_list('oauth2_introspection_auth_method', label='Introspect. Authn. Method',
            values = {'none': 'None', 'basic': 'Basic', 'bearer_token': 'Bearer Token'},
            default = 'basic'
            ) \
          .text('oauth2_revocation_endpoint', label='Revocation endpoint', clipboard_category='revocation_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
        .end_section() \
      .end_section() \
      .start_section('common_configuration', title="Common configuration", collapsible=True) \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('IdP Configuration'+('' if form_content['name'] == '' else ': '+form_content['name']))
    if idp.get('id', '') == '':
      form.add_button('Cancel', '/', display='modify')
    else:
      form.add_button('Cancel', f"display?idpid={idp['id']}", display='modify')
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form
    

  def _generate_idpid(self, name, existing_names):
    
    """
    Génère un identifiant à partir d'un nom
    en ne retenant que les lettres et les chiffres
    et en vérifiant que l'identifiant n'existe pas déjà
    
    S'il existe, ajoute un suffixe numérique
    
    Versions:
      28/02/2021 (mpham) version initiale
      25/12/2024 (mpham) idp est l'identifiant par défaut (si pas donné)
    """
    
    base = name
    ok = False
    rank = 0
    
    while not ok:
      id = ''.join(c for c in base.casefold() if c.isalnum())
      if id == '':
        id = 'idp'
      if rank > 0:
        id = id+str(rank)
      
      if id in existing_names:
        rank = rank+1
      else:
        ok = True
        
    return id
