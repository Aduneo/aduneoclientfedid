"""
Copyright 2023-2025 Aduneo

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


@register_web_module('/client/oidc/admin')
class OIDCClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=False)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application du même type : modify_single
        - modification différencée IdP et les différents clients qu'il gère                    : modify_multi
        
    Versions:
      10/08/2024 (mpham) version initiale
      23/08/2024 (mpham) request parameters
      31/01/2025 (mpham) on n'affiche les paramètres de l'IdP dans tous les cas si on a un seul client ou pas de client
    """

    idp = {}

    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création d'un IdP
      self.modify_single_display()
    else:
      # Modification d'un IdP
      idp = self.conf['idps'].get(idp_id)
      if not idp:
        raise AduneoError(f"IdP {idp_id} not found in configuration")

      oidc_clients = idp.get('oidc_clients', {})  
      
      app_id = self.get_query_string_param('appid', '')
      if app_id == '':
        # Création d'un nouveau SP
        if len(oidc_clients) == 0:
          self.modify_single_display()
        else:
          self.modify_multi_display()
      else:
        # Modification d'un SP
        if len(oidc_clients) == 1:
          self.modify_single_display()
        else:
          self.modify_multi_display()
      

  def modify_single_display(self):
    """ Modification des paramètres de l'IdP et du client sur la même page
    
    Versions:
      10/08/2024 (mpham) version initiale
      23/12/2024 (mpham) possibilité de donner la clé de vérification même en Discovery URI (pour entrer la clé HS256 de Keycloak qui n'est pas aux normes : https://github.com/keycloak/keycloak/issues/13823)
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      30/12/2024 (mpham) End session endpoint HTTP method
      31/01/2025 (mpham) option same_as_oauth2 pour la configuration des endpoints
      31/01/2025 (mpham) création d'un client pour un IdP existant
      25/02/2025 (mpham) modification du nom du client
      08/06/2025 (mpham) DNS override for OIDC token and userinfo endpoints
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {}}
    else:
      idp = self.conf['idps'][idp_id]

    idp_params = idp['idp_parameters']
    oidc_params = idp_params.get('oidc', {})
    oidc_clients = idp.get('oidc_clients', {})
    app_params = oidc_clients.get(app_id, {})

    form_content = {
      'idp_id': idp_id,
      'idp_name': idp.get('name', ''),
      'app_id': app_id,
      'app_name': app_params.get('name', ''),
      'endpoint_configuration': oidc_params.get('endpoint_configuration', 'discovery_uri'),
      'discovery_uri': oidc_params.get('discovery_uri', ''),
      'authorization_endpoint': oidc_params.get('', ''),
      'token_endpoint': oidc_params.get('', ''),
      'userinfo_endpoint': oidc_params.get('userinfo_endpoint', ''),
      'userinfo_method': oidc_params.get('userinfo_method', 'get'),
      'logout_endpoint': oidc_params.get('logout_endpoint', ''),
      'issuer': oidc_params.get('issuer', ''),
      'signature_key_configuration': oidc_params.get('signature_key_configuration', 'discovery_uri'),
      'jwks_uri': oidc_params.get('jwks_uri', ''),
      'signature_key': oidc_params.get('signature_key', ''),
      'token_endpoint_dns_override': oidc_params.get('token_endpoint_dns_override', ''),
      'userinfo_endpoint_dns_override': oidc_params.get('userinfo_endpoint_dns_override', ''),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'post_logout_redirect_uri': app_params.get('post_logout_redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', 'openid'),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'basic'),
      'end_session_endpoint_method': app_params.get('end_session_endpoint_method', 'post'),
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
      .text('idp_name', label='IdP name') \
      .text('app_name', label='Client name') \
      .start_section('op_endpoints', title="OP endpoints") \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration', 'same_as_oauth2': 'Same as OAuth 2'},
          default = 'discovery_uri'
          ) \
        .text('discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[endpoint_configuration] = 'discovery_uri'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .closed_list('userinfo_method', label='Userinfo Request Method',
          values = {'get': 'GET', 'post': 'POST'},
          default = 'get'
          ) \
      .end_section() \
      .start_section('id_token_validation', title="ID token validation") \
        .text('issuer', label='Issuer', clipboard_category='issuer', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .closed_list('signature_key_configuration', label='Signature key configuration',
          values = {'discovery_uri': 'JWKS from discovery URI', 'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[signature_key_configuration] = 'jwks_uri'") \
        .text('signature_key', label='Signature key', displayed_when="@[signature_key_configuration] = 'local_configuration'") \
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
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'basic': 'client_secret_basic', 'form': 'client_secret_post'},
          default = 'basic'
          ) \
        .closed_list('end_session_endpoint_method', label='End session endpoint HTTP method', 
          values={'get': 'GET', 'post': 'POST'},
          default = 'post'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'basic' or @[token_endpoint_auth_method] = 'form'") \
      .end_section() \
      .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=True) \
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
      .start_section('clientfedid_configuration', title="ClientFedID Configuration", collapsible=True, collapsible_default=True) \
        .text('token_endpoint_dns_override', label='Token endpoint DNS override', clipboard_category='token_endpoint_dns_override') \
        .text('userinfo_endpoint_dns_override', label='Userinfo endpoint DNS override', clipboard_category='userinfo_endpoint_dns_override') \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OpenID Connect authentication'+('' if form_content['idp_name'] == '' else ': '+form_content['idp_name']))
    form.set_option('/clipboard/remember_secrets', self.conf.is_on('/preferences/clipboard/remember_secrets', False))

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())


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
      23/08/2024 (mpham) request parameters et strip des données du formulaire
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      30/12/2024 (mpham) End session endpoint HTTP method
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (oidc_<idp_id>_<app_id>) pour les rendre globalement uniques. Les IdP sont en idp_<ipd_id>
      31/01/2025 (mpham) création d'un client pour un IdP existant
      14/02/2025 (mpham) en création, un client vide était créé
      25/02/2025 (mpham) modification du nom du client
      30/05/2025 (mpham) les paramètres OIDC de l'IdP n'était pas créés quand on ajoutait une fonctionnalité OIDC d'un Idp n'en ayant pas
      08/06/2025 (mpham) DNS override for OIDC token and userinfo endpoints
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création de l'IdP
      idp_id = self._generate_unique_id(name=self.post_form['idp_name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      self.conf['idps'][idp_id] = {'idp_parameters': {'oidc': {}}}
    idp = self.conf['idps'][idp_id]

    if app_id == '':
      # Création du SP
      app_id = f'oidc_{idp_id[4:]}_client'
      if not idp.get('oidc_clients'):
        idp['oidc_clients'] = {}
      idp['oidc_clients'][app_id] = {}
    
    idp_params = idp['idp_parameters']
    if not idp_params.get('oidc'):
      idp_params['oidc'] = {}
    oidc_params = idp_params['oidc']
    app_params = idp['oidc_clients'][app_id]

    if self.post_form['idp_name'] == '':
      self.post_form['idp_name'] = idp_id
    idp['name'] = self.post_form['idp_name'].strip()
    
    if self.post_form['app_name'] == '':
      self.post_form['app_name'] = 'OIDC Client'
    app_params['name'] = self.post_form['app_name'].strip()
    
    for item in ['endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'userinfo_method', 'signature_key_configuration', 'jwks_uri', 'signature_key',
    'token_endpoint_dns_override', 'userinfo_endpoint_dns_override']:
      if self.post_form.get(item, '') == '':
        oidc_params.pop(item, None)
      else:
        oidc_params[item] = self.post_form[item].strip()
      
    for item in ['redirect_uri', 'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'end_session_endpoint_method', 'post_logout_redirect_uri',
    'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values']:
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
    
    self.send_redirection(f"/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}")


  @register_page_url(url='modifymulti', method='GET', template='page_default.html', continuous=False)
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
      idp = self.conf['idps'][idp_id]
      if app_id == '':
        # Création du client
        app_params = {}
      else:
        app_params = idp['oidc_clients'][app_id]
        
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
      idp_form = IdPClientAdmin.get_idp_form(self, idp, display_only=True)
          
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


  @register_url(url='modifymulti', method='POST')
  def modify_multi_modify(self):
    """ Crée ou modifie une App OIDC pour un IdP existant (mode multi)
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      26/12/2024 (mpham) version initiale
      30/12/2024 (mpham) End session endpoint HTTP method
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (<idp_id>_oidc_) pour les rendre globalement uniques
    """
    
    idp_id = self.post_form['idp_id']
    idp = self.conf['idps'][idp_id]
    
    app_id = self.post_form['app_id']
    if app_id == '':
      # Création
      if not idp.get('oidc_clients'):
        idp['oidc_clients'] = {}
      
      app_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=idp['oidc_clients'].keys(), default='op', prefix=f'oidc_{idp_id[4:]}_')
      idp['oidc_clients'][app_id] = {}
    
    app_params = idp['oidc_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = app_id

    app_params['name'] = self.post_form['name'].strip()
    
    for item in ['redirect_uri', 'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'end_session_endpoint_method', 'post_logout_redirect_uri',
    'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
    for secret in ['client_secret']:
      if self.post_form.get(secret, '') != '':
        app_params[secret+'!'] = self.post_form[secret]
        
    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}")


  @register_page_url(url='removeapp', method='GET', template='page_default.html', continuous=False)
  def remove_app_display(self):
    """ Page de suppression d'un client OpenID Connect
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oidc_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OpenID Connect client {app_id} does not exist", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      
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
      app_form.set_title('Remove OIDC app '+(' '+app_params['name'] if app_params.get('name') else ''))
      app_form.add_button('Remove', f'removeappconfirmed?idpid={idp_id}&appid={app_id}', display='all')
      app_form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')

      self.add_html(app_form.get_html(display_only=True))
      self.add_javascript(app_form.get_javascript())

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
    Supprime un client OpenID Connect
    
    Versions:
      28/12/2021 (mpham) version initiale
      29/12/2024 (mpham) suppression après page de confirmation
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", action="/")
      idp = self.conf['idps'][idp_id]
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oidc_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OpenID Connect client {app_id} does not exist", action=f"/client/idp/admin/display?idpid={idp_id}")

      del idp['oidc_clients'][app_id]
      Configuration.write_configuration(self.conf)
      self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")
      
    except AduneoError as e:
      self.send_redirection(e.action)


  def get_app_form(handler, app_params:dict):
    """ Retourne un RequesterForm avec un client OIDC (sans les paramètres de l'IdP)
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      app_params: dict avec les paramètres du client OIDC (RP), dans le formalisme du fichier de configuration
             Attention : il faut ajouter deux champs
              - idp_id avec l'identifiant unique de l'IdP
              - app_id avec l'identifiant unique du client
             
    Returns:
      objet RequesterForm
    
    Versions:
      26/12/2024 (mpham) version initiale adaptée de modify_single_display
      30/12/2024 (mpham) End session endpoint HTTP method
    """

    form_content = {
      'idp_id': app_params['idp_id'],
      'app_id': app_params['app_id'],
      'name': app_params.get('name', ''),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'post_logout_redirect_uri': app_params.get('post_logout_redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', 'openid'),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'basic'),
      'end_session_endpoint_method': app_params.get('end_session_endpoint_method', 'post'),
      'display': app_params.get('display', ''),
      'prompt': app_params.get('prompt', ''),
      'max_age': app_params.get('max_age', ''),
      'ui_locales': app_params.get('ui_locales', ''),
      'id_token_hint': app_params.get('id_token_hint', ''),
      'login_hint': app_params.get('login_hint', ''),
      'acr_values': app_params.get('acr_values', ''),
      }
    
    form = CfiForm('oidcadminmulti', form_content, action='modifymulti', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
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
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'basic': 'client_secret_basic', 'form': 'client_secret_post'},
          default = 'basic'
          ) \
        .closed_list('end_session_endpoint_method', label='End session endpoint HTTP method', 
          values={'get': 'GET', 'post': 'POST'},
          default = 'post'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'basic' or @[token_endpoint_auth_method] = 'form'") \
      .end_section() \
      .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=True) \
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
      .end_section()
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form
    

