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
import copy
import html
import json
import time
import traceback
import uuid

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import RequesterForm
from ..BasicXML import BasicXML
from ..Configuration import Configuration
from ..Context import Context
from ..Explanation import Explanation
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler


@register_web_module('/client/cas/logout')
class CASClientLogout(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=False)
  def prepare_request(self):
    """
      Prépare la requête de déconnexion CAS

    Versions:
      28/01/2025 (mpham) version initiale adaptée de CASClientLogin
    """

    self.log_info('--- Start CAS logout flow ---')

    try:

      idp_id = self.get_query_string_param('idpid')
      app_id = self.get_query_string_param('appid')

      if self.context is None:
        if idp_id is None or app_id is None:
          self.send_redirection('/')
          return

        # cas d'un logout sans login préalable, possible en CAS
        idp = copy.deepcopy(self.conf['idps'][idp_id])
        idp_params = idp['idp_parameters'].get('cas')
        if not idp_params:
          raise AduneoError(f"CAS IdP configuration missing for {idp.get('name', idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={idp_id}")
        app_params = idp['cas_clients'][app_id]

        idp_params['name'] = idp['name']

        self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'CAS'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

      else:
        # le logout fait suite à une authentification
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for client {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>Logout from IdP {idp_params['name']} CAS Client {app_params['name']}</h1>")

      form_content = {
        'contextid': self.context['context_id'],  # TODO : remplacer par hr_context ?
        'cas_server_logout_url': idp_params.get('cas_server_url', '')+'/logout',
        'logout_service_url': app_params.get('logout_service_url', ''),
      }
      
      form = RequesterForm('caslogout', form_content, action='/client/cas/logout/sendrequest', mode='new_page', request_url='@[cas_server_logout_url]') \
        .hidden('contextid') \
        .start_section('clientfedid_params', title="ClientFedID Parameters") \
          .text('logout_service_url', label='Service URL', clipboard_category='logout_service_url',
            on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/cas/logout/callback'); }",
          ) \
        .end_section() \
        .start_section('server_configuration', title="Server configuration", collapsible=True, collapsible_default=False) \
          .text('cas_server_logout_url', label='CAS server logout URL', clipboard_category='cas_server_logout_url') \
        .end_section() \
        
      form.set_request_parameters({
          'service': '@[logout_service_url]',
        })
      form.modify_http_parameters({
        'form_method': 'redirect',
        'body_format': 'x-www-form-urlencoded',
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'body_format': False,
        'form_method': False,
        'auth_method': False,
        'verify_certificates': False,
        })
      form.set_option('/requester/include_empty_items', False)

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())

    except AduneoError as error:
      self.add_html('<h4>Error: '+html.escape(str(error))+'</h4>')
      self.add_html(f"""
        <div>
          <span><a class="middlebutton" href="{error.action}">{error.button_label}</a></span>
        </div>
        """)
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Technical error: '+html.escape(str(error))+'</h4>')
      if idp_id:
        self.add_html(f"""
          <div>
            <span><a class="middlebutton" href="/client/idp/admin/display?idpid={idp_id}">IdP homepage</a></span>
          </div>
          """)
      else:
        self.add_html(f"""
          <div>
            <span><a class="middlebutton" href="/">Homepage</a></span>
          </div>
          """)


  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    
    """
    Récupère les informations saisies dans /cas/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /client/cas/logout/preparerequest
    
    Versions:
      28/01/2025 (mpham) version initiale adaptée de OIDCClientLogin
    """
    
    self.log_info('Redirection to IdP requested')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dansle contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      for item in ['cas_server_logout_url']:
        idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dansle contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['logout_service_url']:
        app_params[item] = self.post_form.get(item, '').strip()

      # CAS ne retourne aucun élément dans le callback qui puisse identifier la requête effectuée. Donc on perd le contexte.
      #   On est obligé de conserver un contexte courant, qui est celui de la dernière requête envoyée par le même navigateur
      self.set_session_value('last_cas_context', self.context['context_id'])
      
      # Redirection vers l'IdP
      logout_request = self.post_form['hr_request_url'].strip()+'?'+self.post_form['hr_request_data'].strip()
      self.log_info('Redirecting to:')
      self.log_info(logout_request)
      self.send_redirection(logout_request)

    except Exception as error:
      if not isinstance(error, AduneoError):
        self.log_error(traceback.format_exc())
      self.log_error("""Can't send the request to the IdP, technical error {error}""".format(error=error))
      self.add_html("""<div>Can't send the request to the IdP, technical error {error}</div>""".format(error=error))
      self.send_page()


  @register_page_url(url='callback', method='GET', template='page_default.html', continuous=True)
  def callback(self):
    """ Retour d'authentification depuis l'IdP
    
    Versions:
      28/01/2025 (mpham) version initiale adaptée de OIDCClientLogout
    """

    try:
    
      self.log_info('CAS Authentication callback')

      context_id = self.get_session_value('last_cas_context')
      if context_id:
        self.context = self.get_session_value(context_id)
        if self.context:
          self.logoff('cas_client_'+self.context['idp_id']+'/'+self.context['app_id'])
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_html('<h4>Authentication failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_html(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Authentication failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End CAS logout flow ---')

    self.add_menu() 

    self.send_page()
