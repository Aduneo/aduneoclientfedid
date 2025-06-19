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

import html
import traceback
import uuid

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_page_url, register_url
from ..CfiForm import RequesterForm
from ..Configuration import Configuration
from ..WebRequest import WebRequest
from .FlowHandler import FlowHandler


@register_web_module('/client/oidc/logout')
class OIDCClientLogout(FlowHandler):
  """ OpenID Connect RP-Initiated Logout 1.0
  
    Versions:
      01/03/2021 (mpham) version initiale
      30/12/2024 (mpham) adaptation à RequesterForm
      09/06/2025 (mpham) nouvelle organisation du contexte
  """
 
  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=True)
  def prepare_request(self):
    
    try:

      self.log_info('--- Start OpenID Connect logout flow ---')

      # Récupération du contexte d'authentification
      if not self.context:
        idp_id = self.get_query_string_param('idpid', '')
        raise AduneoError("Can't retrieve request context from session", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      # Récupération des paramètres nécessaires à la déconnexion
      idp_params = self.context.idp_params
      oidc_idp_params = idp_params['oidc']

      app_params = None
      app_id = self.get_query_string_param('appid', '')
      app_params = self.context.app_params.get(app_id, None)
      if not app_params:
        # les paramètres du client ne sont pas dans le contexte, on va les chercher dans la configuration
        idp_id = self.get_query_string_param('idpid', '')
        if idp_id == '':
          raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
        idp = copy.deepcopy(self.conf['idps'][idp_id])
        app_params = idp['oidc_clients'].get(app_id)
        if not app_params:
          raise AduneoError(f"OpenID Connect client {app_id} does not exist for IdP {idp_id}", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")

      # Récupération des jetons d'identité pour le client
      id_tokens = {'__none__': 'None', '__input__': 'Direct Input'}
      default_id_token = None
      for token_wrapper_key in sorted(self.context['id_tokens'].keys(), reverse=True):
        token_wrapper = self.context['id_tokens'][token_wrapper_key]
        if token_wrapper['app_id'] == app_id:
          id_tokens[token_wrapper['id_token']] = token_wrapper['name']
          if not default_id_token:
              default_id_token = token_wrapper['id_token']  

      state = str(uuid.uuid4())

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(state, self.context['context_id'])

      on_id_token_change = """
        if (cfiForm.getThisFieldValue() == '__none__') { 
          cfiForm.setFieldValue('id_token_hint', ''); 
        } else if (cfiForm.getThisFieldValue() != '__input__') { 
          cfiForm.setFieldValue('id_token_hint', cfiForm.getThisFieldValue());
        }
        """

      form_content = {
        'hr_context': self.context['context_id'],
        'end_session_endpoint': oidc_idp_params.get('end_session_endpoint', ''),
        'end_session_endpoint_method': app_params.get('end_session_endpoint_method', 'post'),
        'id_token': default_id_token if default_id_token else '__input__',
        'id_token_hint': default_id_token if default_id_token else '',
        'logout_hint': app_params.get('logout_hint', ''),
        'client_id': app_params.get('client_id', ''),
        'post_logout_redirect_uri': app_params.get('post_logout_redirect_uri', ''),
        'ui_locales': app_params.get('ui_locales', ''),
        'state': state,
      }
      
      form = RequesterForm('oidclogout', form_content, action='sendrequest', mode='new_page', request_url='@[end_session_endpoint]') \
        .start_section('clientfedid_params', title="ClientFedID parameters") \
          .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri') \
        .end_section() \
        .start_section('op_endpoints', title="OP endpoints", collapsible=True, collapsible_default=False) \
          .text('end_session_endpoint', label='End session endpoint', clipboard_category='end_session_endpoint') \
        .end_section() \
        .start_section('client_params', title="Client parameters", collapsible=True, collapsible_default=False) \
          .text('client_id', label='Client ID', clipboard_category='client_id') \
          .closed_list('end_session_endpoint_method', label='End session endpoint HTTP method', 
            values={'get': 'GET', 'post': 'POST'},
            default = 'post'
            ) \
        .end_section() \
        .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=False) \
          .text('state', label='State', clipboard_category='state') \
          .closed_list('id_token', label='ID token', 
            values = id_tokens,
            default = default_id_token,
            on_change = on_id_token_change,
            ) \
          .text('id_token_hint', label='ID Token Hint', clipboard_category='id_token_hint', displayed_when="@[id_token] = '__input__'") \
          .text('ui_locales', label='UI Locales', clipboard_category='ui_locales') \
          .text('logout_hint', label='Logout Hint', clipboard_category='login_hint') \
        .end_section() \

      form.set_request_parameters({
          'id_token_hint': '@[id_token_hint]',
          'logout_hint': '@[logout_hint]',
          'client_id': '@[client_id]',
          'post_logout_redirect_uri': '@[post_logout_redirect_uri]',
          'state': '@[state]',
          'ui_locales': '@[ui_locales]',
        })
      form.modify_http_parameters({
        'form_method': '@[end_session_endpoint_method]',
        'body_format': 'x-www-form-urlencoded',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'body_format': False,
        'form_method': True,
        'auth_method': False,
        'verify_certificates': True,
        })
      form.set_option('/requester/include_empty_items', False)

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())

    except AduneoError as e:

      self.log_error(f'Error in logout flow: {e}')

      self.add_html(f"""
        <div>
          Error: {e}
        </div>
        <div>
          <span><a class="smallbutton" href="{e.action}">{e.button_label}</a></span>
        </div>
        """)
    
    self.send_page()
    
    

  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    
    """
    Récupère les informations saisies dans /oidc/client/logout/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oidc/client/logout/preparerequest et placée dans le paramètre authentication_request
    
    Versions:
      30/12/2024 (mpham) version initiale adaptée du login OIDC
      09/06/2025 (mpham) nouvelle organisation du contexte
    """
    
    self.log_info('OIDC logout flow: sending the request to the IdP')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      oidc_idp_params = idp_params['oidc']
      for item in ['end_session_endpoint']:
        oidc_idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dansle contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['end_session_endpoint_method', 'id_token_hint', 'logout_hint', 'client_id', 'post_logout_redirect_uri', 'display', 'prompt', 'max_age', 'ui_locales', 'ui_locales']:
        app_params[item] = self.post_form.get(item, '').strip()
      
      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'

      RequesterForm.send_form(self, self.post_form)

    except Exception as error:
      if not isinstance(error, AduneoError):
        self.log_error(traceback.format_exc())
      self.log_error("""Can't send the request to the IdP, technical error {error}""".format(error=error))
      self.add_html("""<div>Can't send the request to the IdP, technical error {error}</div>""".format(error=error))
      self.send_page()














  #@register_url(url='sendrequest', method='POST')
  def old_send_request(self):
    
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


  @register_page_url(url='callback', method='GET', template='page_default.html', continuous=True)
  def callback(self):

    try:

      self.add_html('<h2>Logout callback</h2>')
      self.add_html('User successfully logged out')

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      if not idp_state:
        raise AduneoError(self.log_error(f"Can't retrieve request context from state because state in not present in callback query string {self.hreq.path}"))
      self.log_info('for state: '+idp_state)

      context_id = self.get_session_value(idp_state)
      if not context_id:
        raise AduneoError(self.log_error(f"Can't retrieve request context from state because context id not found in session for state {idp_state}"))

      self.context = self.get_session_value(context_id)
      if not self.context:
        raise AduneoError(self.log_error(f"Can't retrieve request context because context id {context_id} not found in session"))
        
      self.logoff('oidc_client_'+self.context['idp_id']+'/'+self.context['app_id'])

      self.add_menu()
      self.send_page()
      
    except AduneoError as error:
      self.add_html('<h4>Logout error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Logout error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()

    self.log_info('--- End OpenID Connect logout flow ---')
    

