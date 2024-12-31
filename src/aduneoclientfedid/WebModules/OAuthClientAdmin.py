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
import copy
import html
import uuid

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
      23/12/2024 (mpham) les valeurs des select sont maintenant toutes des constantes du type metadata_uri et non plus des libellés comme Authorization Server Metadata URI
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      app_id = 'client'
      idp = {'idp_parameters': {'oidc': {}}, 'oauth2_clients': {app_id: {}}}
    if idp_id != '' and app_id != '':
      idp = copy.deepcopy(self.conf['idps'][idp_id])
    idp_params = idp['idp_parameters']
    oauth2_params = idp_params['oauth2']
    app_params = idp['oauth2_clients'][app_id]

    form_content = {
      'idp_id': idp_id,
      'app_id': app_id,
      'name': idp.get('name', ''),
      'endpoint_configuration': oauth2_params.get('endpoint_configuration', 'metadata_uri'),
      'metadata_uri': oauth2_params.get('metadata_uri', ''),
      'authorization_endpoint': oauth2_params.get('', ''),
      'token_endpoint': oauth2_params.get('', ''),
      'introspection_endpoint': oauth2_params.get('introspection_endpoint', ''),
      'introspection_method': oauth2_params.get('introspection_method', 'get'),
      'revocation_endpoint': oauth2_params.get('revocation_endpoint', ''),
      'signature_key_configuration': oauth2_params.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': oauth2_params.get('jwks_uri', ''),
      'signature_key': oauth2_params.get('signature_key', ''),
      'oauth_flow': app_params.get('oauth_flow', 'Authorization Code'),
      'pkce_method': app_params.get('pkce_method', 'S256'),
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
          values={'metadata_uri': 'Authorization Server Metadata URI', 'local_configuration': 'Local configuration'},
          default = 'metadata_uri'
          ) \
        .text('metadata_uri', label='AS Metadata URI', clipboard_category='metadata_uri', displayed_when="@[endpoint_configuration] = 'metadata_uri'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .closed_list('introspection_method', label='Introspect. Request Method',
          values = {'get': 'GET', 'post': 'POST'},
          default = 'get'
          ) \
        .text('revocation_endpoint', label='Revocation endpoint', clipboard_category='revocation_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('client_endpoints', title="Client Endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oauth2/login/callback'); }" 
          ) \
      .end_section() \
      .start_section('oauth2_configuration', title="OAuth 2 Configuration") \
        .closed_list('oauth_flow', label='OAuth Flow', 
          values={'authorization_code': 'Authorization Code', 'authorization_code_pkce': 'Authorization Code with PKCE', 'resource_owner_password_predentials': 'Resource Owner Password Credentials'},
          default = 'authorization_code'
          ) \
        .closed_list('pkce_method', label='PKCE Code Challenge Method', displayed_when="@[oauth_flow] = 'authorization_code_pkce'",
          values={'plain': 'plain', 'S256': 'S256'},
          default = 'S256'
          ) \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('response_type', label='Reponse Type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
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
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (oauth2_<idp_id>_<app_id>) pour les rendre globalement uniques. Les IdP sont en idp_<ipd_id>
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      app_id = f'oauth2_{idp_id[4:]}_client'
      self.conf['idps'][idp_id] = {'idp_parameters': {'oauth2': {}}, 'oauth2_clients': {app_id: {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    oauth2_params = idp_params['oauth2']
    app_params = idp['oauth2_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name']
    app_params['name'] = 'OAuth2 Client'
    
    for item in ['endpoint_configuration', 'metadata_uri', 'authorization_endpoint', 'token_endpoint', 
    'revocation_endpoint', 'introspection_endpoint', 'introspection_method', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
      if self.post_form.get(item, '') == '':
        oauth2_params.pop(item, None)
      else:
        oauth2_params[item] = self.post_form[item].strip()
      
    for item in ['redirect_uri', 'client_id', 'oauth_flow', 'pkce_method', 'scope', 'response_type', 'token_endpoint_auth_method']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
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


  @register_page_url(url='modifymulti', method='GET', template='page_default.html', continuous=True)
  def modify_multi_endpoint(self):
    self.modify_multi_display()

  
  def modify_multi_display(self):
    """ Modification des paramètres du client (mais pas de l'IdP)
    
    Versions:
      26/12/2024 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création de l'IdP, on redirige vers Single
      self.modify_single_display()
    else:
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      if app_id == '':
        # Création du client
        app_params = {}
      else:
        app_params = idp['oauth2_clients'][app_id]
        
      # Affichage de l'IdP
      self.add_html(f"<h1>IdP {idp['name']}</h1>")
      idp_panel_uuid = str(uuid.uuid4())
      self.add_html("""
        <div>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
        </div>
        """.format(
          div_id = idp_panel_uuid,
          ))
          
      from .IdPClientAdmin import IdPClientAdmin
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = idp_panel_uuid,
          form = idp_form.get_html(display_only=True),
          ))

      app_params['idp_id'] = idp_id
      app_params['app_id'] = app_id
      app_form = self.get_app_form(app_params)

      self.add_html(app_form.get_html())
      self.add_javascript(app_form.get_javascript())
      
      self.send_page()


  @register_url(url='modifymulti', method='POST')
  def modify_multi_modify(self):
    """ Crée ou modifie une App OAuth 2 pour un IdP existant (mode multi)
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      26/12/2024 (mpham) version initiale
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (<idp_id>_oidc_) pour les rendre globalement uniques
    """
    
    idp_id = self.post_form['idp_id']
    idp = self.conf['idps'][idp_id]
    
    app_id = self.post_form['app_id']
    if app_id == '':
      # Création
      if not idp.get('oauth2_clients'):
        idp['oauth2_clients'] = {}
      
      app_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=idp['oauth2_clients'].keys(), default='op', prefix=f'oauth2_{idp_id[4:]}_')
      idp['oauth2_clients'][app_id] = {}
    
    app_params = idp['oauth2_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = app_id

    app_params['name'] = self.post_form['name'].strip()
    
    for item in ['redirect_uri', 'client_id', 'oauth_flow', 'pkce_method', 'scope', 'response_type', 'token_endpoint_auth_method']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
    for secret in ['client_secret']:
      if self.post_form.get(secret, '') != '':
        app_params[secret+'!'] = self.post_form[secret]
        
    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}")
    

  @register_page_url(url='removeapp', method='GET', template='page_default.html', continuous=True)
  def remove_app_display(self):
    """ Page de suppression d'un client
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oauth2_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OAuth 2 client {app_id} does not exist", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      
      # Affichage de l'IdP
      self.add_html(f"<h1>IdP {idp['name']}</h1>")
      idp_panel_uuid = str(uuid.uuid4())
      self.add_html("""
        <div>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
        </div>
        """.format(
          div_id = idp_panel_uuid,
          ))
          
      from .IdPClientAdmin import IdPClientAdmin
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = idp_panel_uuid,
          form = idp_form.get_html(display_only=True),
          ))

      app_params['idp_id'] = idp_id
      app_params['app_id'] = app_id
      app_form = self.get_app_form(app_params)
      app_form.set_title('Remove OAuth 2 app '+(' '+app_params['name'] if app_params.get('name') else ''))
      app_form.add_button('Remove', f'removeappconfirmed?idpid={idp_id}&appid={app_id}', display='all')
      app_form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')

      self.add_html(app_form.get_html(display_only=True))
      self.add_javascript(app_form.get_javascript())
      
      self.send_page()

    except AduneoError as e:
      self.add_html(f"""
        <div>
          Error: {e}
        </div>
        <div>
          <span><a class="smallbutton" href="{e.action}">{e.button_label}</a></span>
        </div>
        """)


  @register_url(url='removeappconfirmed', method='GET')
  def remove_app_remove(self):
    """
    Supprime un client OAuth 2
    
    29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", action="/")
      idp = self.conf['idps'][idp_id]
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oauth2_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OAuth 2 client {app_id} does not exist", action=f"/client/idp/admin/display?idpid={idp_id}")

      del idp['oauth2_clients'][app_id]
      Configuration.write_configuration(self.conf)
      self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")
      
    except AduneoError as e:
      self.send_redirection(e.action)


  def get_app_form(handler, app_params:dict):
    """ Retourne un RequesterForm avec un client OAuth 2 (sans les paramètres de l'IdP)
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      app_params: dict avec les paramètres du client OAuth 2, dans le formalisme du fichier de configuration
             Attention : il faut ajouter deux champs
              - idp_id avec l'identifiant unique de l'IdP
              - app_id avec l'identifiant unique du client
             
    Returns:
      objet RequesterForm
    
    Versions:
      26/12/2024 (mpham) version initiale
    """

    form_content = {
      'idp_id': app_params['idp_id'],
      'app_id': app_params['app_id'],
      'name': app_params.get('name', ''),
      'oauth_flow': app_params.get('oauth_flow', 'Authorization Code'),
      'pkce_method': app_params.get('pkce_method', 'S256'),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', ''),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
      }
    
    form = CfiForm('oauth2adminmulti', form_content, action='modifymulti', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('client_endpoints', title="Client Endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oauth2/login/callback'); }" 
          ) \
      .end_section() \
      .start_section('oauth2_configuration', title="OAuth 2 Configuration") \
        .closed_list('oauth_flow', label='OAuth Flow', 
          values={'authorization_code': 'Authorization Code', 'authorization_code_pkce': 'Authorization Code with PKCE', 'resource_owner_password_predentials': 'Resource Owner Password Credentials'},
          default = 'authorization_code'
          ) \
        .closed_list('pkce_method', label='PKCE Code Challenge Method', displayed_when="@[oauth_flow] = 'authorization_code_pkce'",
          values={'plain': 'plain', 'S256': 'S256'},
          default = 'S256'
          ) \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('response_type', label='Reponse Type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() 
      
    form.set_title('OAuth 2 Authorization'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.add_button('Cancel', f"/client/idp/admin/display?idpid={app_params['idp_id']}", display='modify')
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form


  @register_page_url(url='modifyapi', method='GET', template='page_default.html', continuous=True)
  def modify_api_display(self):
    """ Modification des paramètres d'une API
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('idpid', '')
    api_id = self.get_query_string_param('apiid', '')
    if idp_id == '':
      # l'IdP n'existe pas, on redirige vers la page d'accueil
      self.send_redirection('/')
    else:
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      if api_id == '':
        # Création de l'API
        api_params = {}
      else:
        api_params = idp['oauth2_apis'][api_id]
        
      # Affichage de l'IdP
      self.add_html(f"<h1>IdP {idp['name']}</h1>")
      idp_panel_uuid = str(uuid.uuid4())
      self.add_html("""
        <div>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
        </div>
        """.format(
          div_id = idp_panel_uuid,
          ))
          
      from .IdPClientAdmin import IdPClientAdmin
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = idp_panel_uuid,
          form = idp_form.get_html(display_only=True),
          ))

      api_params['idp_id'] = idp_id
      api_params['api_id'] = api_id
      api_form = self.get_api_form(api_params)

      self.add_html(api_form.get_html())
      self.add_javascript(api_form.get_javascript())
      
      self.send_page()


  @register_url(url='modifyapi', method='POST')
  def modify_api_modify(self):
    """ Crée ou modifie une API OAuth 2 pour un IdP existant
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      29/12/2024 (mpham) version initiale
    """
    
    idp_id = self.post_form['idp_id']
    idp = self.conf['idps'][idp_id]
    
    api_id = self.post_form['api_id']
    if api_id == '':
      # Création
      if not idp.get('oauth2_apis'):
        idp['oauth2_apis'] = {}
      
      api_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=idp['oauth2_apis'].keys(), default='op', prefix=f'api_{idp_id[4:]}_')
      idp['oauth2_apis'][api_id] = {}
    
    api_params = idp['oauth2_apis'][api_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = api_id

    api_params['name'] = self.post_form['name'].strip()
    
    for item in ['introspection_http_method', 'introspection_auth_method', 'login']:
      if self.post_form.get(item, '') == '':
        api_params.pop(item, None)
      else:
        api_params[item] = self.post_form[item].strip()
      
    for secret in ['secret']:
      if self.post_form.get(secret, '') != '':
        api_params[secret+'!'] = self.post_form[secret]
        
    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")

    
  @register_page_url(url='removeapi', method='GET', template='page_default.html', continuous=True)
  def remove_api_display(self):
    """ Suppression d'une API
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('idpid', '')
    api_id = self.get_query_string_param('apiid', '')
    if idp_id == '':
      # l'IdP n'existe pas, on redirige vers la page d'accueil
      self.send_redirection('/')
    else:
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      if api_id == '':
        # Création de l'API
        self.send_redirection(f'/client/idp/admin/display?idpid={idp_id}')
      else:
        api_params = idp['oauth2_apis'][api_id]
        
        # Affichage de l'IdP
        self.add_html(f"<h1>IdP {idp['name']}</h1>")
        idp_panel_uuid = str(uuid.uuid4())
        self.add_html("""
          <div>
            <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
          </div>
          """.format(
            div_id = idp_panel_uuid,
            ))
            
        from .IdPClientAdmin import IdPClientAdmin
        idp['id'] = idp_id
        idp_form = IdPClientAdmin.get_idp_form(self, idp)
            
        self.add_html("""
          <div id="panel_{div_id}" style="display: none;">{form}</div>
          """.format(
            div_id = idp_panel_uuid,
            form = idp_form.get_html(display_only=True),
            ))

        api_params['idp_id'] = idp_id
        api_params['api_id'] = api_id
        api_form = self.get_api_form(api_params)
        api_form.set_title('Remove OAuth 2 API '+(' '+api_params['name'] if api_params.get('name') else ''))
        api_form.add_button('Remove', f'removeapiconfirmed?idpid={idp_id}&apiid={api_id}', display='all')
        api_form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')

        self.add_html(api_form.get_html(display_only=True))
        self.add_javascript(api_form.get_javascript())
        
        self.send_page()


  @register_url(url='removeapiconfirmed', method='GET')
  def remove_api_remove(self):
    """ Suppression d'une API
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('idpid', '')
    api_id = self.get_query_string_param('apiid', '')
    if idp_id == '':
      # l'IdP n'existe pas, on redirige vers la page d'accueil
      self.send_redirection('/')
    else:
      idp = self.conf['idps'][idp_id]
      if api_id == '':
        # Création de l'API
        self.send_redirection(f'/client/idp/admin/display?idpid={idp_id}')
      else:
        del idp['oauth2_apis'][api_id]
        Configuration.write_configuration(self.conf)
        self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")


  def get_api_form(handler, api_params:dict):
    """ Retourne un RequesterForm avec la définition d'une API, c'est-à-dire d'un Resource Server (RS) OAuth 2 qui reçoit une jeton et le valide par introspection
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      api_params: dict avec les paramètres de l'API, dans le formalisme du fichier de configuration
             Attention : il faut ajouter deux champs
              - idp_id avec l'identifiant unique de l'IdP
              - api_id avec l'identifiant unique de l'API
             
    Returns:
      objet RequesterForm
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    form_content = {
      'idp_id': api_params['idp_id'],
      'api_id': api_params['api_id'],
      'name': api_params.get('name', ''),
      'introspection_http_method': api_params.get('introspection_http_method', 'inherit_from_idp'),
      'introspection_auth_method': api_params.get('introspection_auth_method', 'inherit_from_idp'),
      'login': api_params.get('login', ''),
      'secret': '',
      }
    
    form = CfiForm('oauth2api', form_content, action='modifyapi', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('api_id') \
      .text('name', label='Name') \
      .closed_list('introspection_http_method', label='Introspect. request method',
        values = {'inherit_from_idp': 'Inherit from IdP', 'get': 'GET', 'post': 'POST'},
        default = 'inherit_from_idp'
        ) \
      .closed_list('introspection_auth_method', label='Introspect. authn scheme',
        values = {'inherit_from_idp': 'Inherit from IdP', 'none': 'None', 'basic': 'Basic', 'bearer_token': 'Bearer Token'},
        default = 'inherit_from_idp'
        ) \
      .text('login', label='Login', clipboard_category='client_id') \
      .password('secret', label='Secret', clipboard_category='client_secret!')
      
    form.set_title('OAuth 2 API'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.add_button('Cancel', f"/client/idp/admin/display?idpid={api_params['idp_id']}", display='modify')
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form
