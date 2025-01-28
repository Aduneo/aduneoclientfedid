"""
Copyright 2025 Aduneo

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


@register_web_module('/client/cas/admin')
class CASClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=False)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application : modify_single
        - modification différencée IdP et les différents clients qu'il gère       : modify_multi
        
    Versions:
      24/01/2025 (mpham) version initiale copiée et adaptée de OIDCClientAdmin
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
      cas_clients = idp.get('cas_clients', {})  
        
      if len(cas_clients) == 1 and (len(oidc_clients) + len(oauth2_clients) + len(saml_clients) == 0):
        self.modify_single_display()
      else:
        self.modify_multi_display()
      

  def modify_single_display(self):
    """ Modification des paramètres du serveur CAS et du client sur la même page
    
    Versions:
      24/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      app_id = 'client'
      idp = {'idp_parameters': {'cas': {}}, 'cas_clients': {app_id: {}}}
    if idp_id != '' and app_id != '':
      idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    cas_params = idp_params['cas']
    app_params = idp['cas_clients'][app_id]

    form_content = {
      'idp_id': idp_id,
      'app_id': app_id,
      'name': idp.get('name', ''),
      'cas_server_url': cas_params.get('cas_server_url', ''),
      'service_url': app_params.get('service_url', ''),
      'renew': app_params.get('renew', '[not set]'),
      'gateway': app_params.get('renew', '[not set]'),
      'method': app_params.get('method', 'get'),
      'ticket_validation_version': app_params.get('ticket_validation_version', 'cas_3.0'),
      'validation_response_format': app_params.get('validation_response_format', 'XML'),
      'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('casadminsingle', form_content, action='modifyclientsingle', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('server_configuration', title="Server configuration") \
        .text('cas_server_url', label='CAS server URL', clipboard_category='cas_server_url') \
      .end_section() \
      .start_section('client_configuration', title="CAS client configuration") \
        .text('service_url', label='Service URL', clipboard_category='service_url',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/cas/login/callback'); }" 
          ) \
        .open_list('renew', label='Renew', 
          hints = ['[not set]', 'true']
          ) \
        .open_list('gateway', label='Gateway', 
          hints = ['[not set]', 'true']
          ) \
        .closed_list('method', label='Method',
          values = {'get': 'GET', 'post': 'POST', 'header': 'HEADER'},
          default = 'get'
          ) \
        .closed_list('ticket_validation_version', label='Ticket validation version',
          values = {'cas_1.0': 'CAS 1.0', 'cas_2.0': 'CAS 2.0', 'cas_3.0': 'CAS 3.0'},
          default = 'cas_3.0'
          ) \
      .end_section() \
      .start_section('logout_configuration', title="Logout configuration") \
        .text('logout_service_url', label='Logout service URL', clipboard_category='logout_service_url',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/cas/logout/callback'); }" 
          ) \
      .end_section() \
      .start_section('ticket_validation', title="Ticket validation") \
        .closed_list('validation_response_format', label='Validation response format',
          values = {'xml': 'XML', 'json': 'JSON'},
          default = 'XML'
          ) \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('CAS authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', self.conf.is_on('/preferences/clipboard/remember_secrets', False))

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())


  @register_url(url='modifyclientsingle', method='POST')
  def modify_single_modify(self):
    """ Crée ou modifie un IdP + App CAS (mode single) dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      24/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      app_id = f'cas_{idp_id[4:]}_client'
      self.conf['idps'][idp_id] = {'idp_parameters': {'cas': {}}, 'cas_clients': {app_id: {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    cas_params = idp_params['cas']
    app_params = idp['cas_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name'].strip()
    app_params['name'] = 'CAS Client'
    
    for item in ['cas_server_url']:
      if self.post_form.get(item, '') == '':
        cas_params.pop(item, None)
      else:
        cas_params[item] = self.post_form[item].strip()

    for item in ['service_url', 'renew', 'gateway', 'method', 'ticket_validation_version', 'validation_response_format', 'logout_service_url']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
    for item in ['verify_certificates']:
      if item in self.post_form:
        idp_params[item] = 'on'
      else:
        idp_params[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/cas/login/preparerequest?idpid={idp_id}&appid={app_id}")

















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
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
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
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .closed_list('end_session_endpoint_method', label='End session endpoint HTTP method', 
          values={'get': 'GET', 'post': 'POST'},
          default = 'post'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
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
    

