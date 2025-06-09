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
from ..WebRequest import WebRequest
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler


@register_web_module('/client/cas/login')
class CASClientLogin(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=False)
  def prepare_request(self):
    """
      Prépare la requête d'authentification CAS

    Versions:
      24/01/2025 (mpham) version initiale adaptée de OIDCClientLogin
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """

    self.log_info('--- Start CAS flow ---')

    try:

      idp_id = self.get_query_string_param('idpid')
      app_id = self.get_query_string_param('appid')

      new_auth = True
      if self.context is None:
        if idp_id is None or app_id is None:
          self.send_redirection('/')
          return
      else:
        new_auth = False
      
      if self.get_query_string_param('newauth'):
        new_auth = True

      if new_auth:
        # Nouvelle requête
        idp = copy.deepcopy(self.conf['idps'][idp_id])
        idp_params = idp['idp_parameters']
        cas_idp_params = idp_params['cas']
        if not cas_idp_params:
          raise AduneoError(f"CAS IdP configuration missing for {idp.get('name', idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={idp_id}")
        app_params = idp['cas_clients'][app_id]

        # On récupère name des paramètres de l'IdP
        idp_params['name'] = idp['name']

        # si le contexte existe, on le conserve (cas newauth)
        if self.context is None:
          self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'CAS'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

      else:
        # Rejeu de requête (conservée dans la session)
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        cas_idp_params = idp_params['cas']
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for client {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>Authentication for IdP {idp_params['name']} CAS Client {app_params['name']}</h1>")

      # ticket validation version
      cas_server_validate_url = cas_idp_params.get('cas_server_url', '')
      if app_params.get('ticket_validation_version') == 'cas_3.0':
        cas_server_validate_url += '/p3/serviceValidate'
      elif app_params.get('ticket_validation_version') == 'cas_2.0':
        cas_server_validate_url += '/serviceValidate'
      else:
        cas_server_validate_url += '/validate'
      self.log_info(('  ' * 1) + f"validation version {app_params.get('ticket_validation_version')}")
      self.log_info(('  ' * 1) + f"validation URL {cas_server_validate_url}")

      form_content = {
        'contextid': self.context['context_id'],  # TODO : remplacer par hr_context ?
        'cas_server_login_url': cas_idp_params.get('cas_server_url', '')+'/login',
        'service_url': app_params.get('service_url', ''),
        'cas_server_validate_url': cas_server_validate_url,
        'renew': app_params.get('renew', '[not set]'),
        'gateway': app_params.get('gateway', '[not set]'),
        'method': app_params.get('method', ''),
        'validation_response_format': app_params.get('validation_response_format', 'XML'),
      }
      
      form = RequesterForm('casauth', form_content, action='/client/cas/login/sendrequest', mode='new_page', request_url='@[cas_server_login_url]') \
        .hidden('contextid') \
        .start_section('clientfedid_params', title="ClientFedID Parameters") \
          .text('service_url', label='Service URL', clipboard_category='service_url') \
        .end_section() \
        .start_section('server_configuration', title="Server configuration", collapsible=True, collapsible_default=False) \
          .text('cas_server_login_url', label='CAS server login URL', clipboard_category='cas_server_login_url') \
          .text('cas_server_validate_url', label='CAS server validate URL', clipboard_category='cas_server_validate_url') \
        .end_section() \
        .start_section('client_configuration', title="Client configuration", collapsible=True, collapsible_default=False) \
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
        .end_section() \
        .start_section('ticket_validation', title="Ticket validation") \
          .closed_list('validation_response_format', label='Validation response format',
            values = {'xml': 'XML', 'json': 'JSON'},
            default = 'xml'
            ) \
        .end_section() \

      form.set_request_parameters({
          'service': '@[service_url]',
          'renew': '@[renew]',
          'gateway': '@[gateway]',
          'method': '@[method]',
        })
      form.modify_http_parameters({
        'form_method': 'redirect',
        'body_format': 'x-www-form-urlencoded',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'body_format': False,
        'form_method': False,
        'auth_method': False,
        'verify_certificates': True,
        })
      form.set_data_generator_code("""
        if (cfiForm.getField('renew').value == '[not set]') {
          delete paramValues['renew'];
        }
        if (cfiForm.getField('gateway').value == '[not set]') {
          delete paramValues['gateway'];
        }
        return paramValues;
      """)
      form.set_option('/requester/include_empty_items', True)

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
    Redirige vers l'IdP grâce à la requête générée dans /cas/client/preparerequest et placée dans le paramètre authentication_request
    
    Versions:
      24/01/2025 (mpham) version initiale adaptée de OIDCClientLogin
      27/02/2025 (mpham) les paramètres IdP n'étaient pas mis à jour au bon endroit
    """
    
    self.log_info('Redirection to IdP requested')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dansle contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      cas_idp_params = idp_params['cas']
      for item in ['cas_server_login_url', 'cas_server_validate_url']:
        cas_idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dansle contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['service_url', 'renew', 'gateway', 'method', 'validation_response_format']:
        app_params[item] = self.post_form.get(item, '').strip()

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'
        
      # CAS ne retourne aucun élément dans le callback qui puisse identifier la requête effectuée. Donc on perd le contexte.
      #   On est obligé de conserver un contexte courant, qui est celui de la dernière requête envoyée par le même navigateur
      self.set_session_value('last_cas_context', self.context['context_id'])
      
      # Redirection vers l'IdP
      authentication_request = self.post_form['hr_request_url'].strip()+'?'+self.post_form['hr_request_data'].strip()
      self.log_info('Redirecting to:')
      self.log_info(authentication_request)
      self.send_redirection(authentication_request)

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
      26/01/2025 (mpham) version initiale adaptée de OIDCClientLogin
      18/01/2025 (mpham) parsing de la réponse (XML ou JSON)
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """

    self.add_javascript_include('/javascript/resultTable.js')
    try:
    
      self.log_info('CAS Authentication callback')

      context_id = self.get_session_value('last_cas_context')
      if not context_id:
        raise AduneoError(f"Can't retrieve last CAS request context from no CAS request has been found in session")

      self.context = self.get_session_value(context_id)
      if not self.context:
        raise AduneoError(f"Can't retrieve request context because context id {context_id} not found in session")
      
      # extraction des informations utiles de la session
      idp_id = self.context.idp_id
      app_id = self.context.app_id
      idp_params = self.context.idp_params
      cas_idp_params = idp_params['cas']
      app_params = self.context.last_app_params

      self.add_html(f"<h3>CAS callback from {html.escape(idp_params['name'])} for client {html.escape(app_params['name'])}</h3>")

      self.start_result_table()
      
      cas_ticket = self.get_query_string_param('ticket')
      if cas_ticket:
        self.log_info(f"  ticket in query string: {cas_ticket}")
        self.add_result_row('Ticket in query string', cas_ticket, 'cas_ticket')
      else:
        cas_ticket = self.post_form.get('ticket')
        if cas_ticket:
          self.log_info(f"  ticket in body: {cas_ticket}")
          self.add_result_row('Ticket in body', cas_ticket, 'cas_ticket')
        else:
          cas_ticket = self.headers.get('ticket')
          if cas_ticket:
            self.log_info(f"  ticket in header: {cas_ticket}")
            self.add_result_row('Ticket in header', cas_ticket, 'cas_ticket')
          else:
            raise AduneoError(self.log_error("ticket not found in CAS response"))

      # validation du ticket
      self.log_info("  Start validating ticket")
      cas_server_validate_url = cas_idp_params['cas_server_validate_url']

      self.add_result_row('Validate URL', cas_server_validate_url, 'cas_server_validate_url')
      self.end_result_table()
      self.add_html('<div class="intertable">Validating ticket...</div>')

      data = {
        'service': app_params['service_url'],
        'ticket': cas_ticket,
        'format': app_params.get('validation_response_format', 'XML'),
        }
      
      try:
        self.log_info(f"  Connecting to {cas_server_validate_url}")
        self.log_info(f"  with data {data}")
        verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        r = WebRequest.get(cas_server_validate_url, query=data, verify_certificate=verify_certificates)
      except Exception as error:
        self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status == 200:
        self.add_html('<div class="intertable">Success</div>')
      else:
        self.add_html('<div class="intertable">Error, status code '+str(r.status)+'</div>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status)+", "+str(r.data)))

      self.log_info("IdP response:")
      self.log_info(r.data)

      self.start_result_table()

      authentication_successful = False
      if app_params.get('validation_response_format') == 'json':
        response = r.json()
        self.add_result_row('CAS response', json.dumps(response, indent=2), '')
        service_response = response.get('serviceResponse')
        if service_response:
          if service_response.get('authenticationSuccess'):
            authentication_successful = True
      else:
        self.add_result_row('CAS response', r.text, '')
        response = BasicXML.parse(r.text)
        service_response = response.get('cas:serviceResponse')
        if service_response:
          if service_response.get('cas:authenticationSuccess'):
            authentication_successful = True

      self.end_result_table()
      if authentication_successful:
        self.add_html('<h3>Authentication successful</h3>')
      else:
        self.add_html('<h3>Authentication failed</h3>')
      
      # on considère qu'on est bien loggé (le ticket n'est pas utilisable, on ne le conserve que pour information
      self.context['cas_tickets'][str(time.time())] = cas_ticket
      self.logon('cas_client_'+idp_id+'/'+app_id, cas_ticket)
      
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

    self.log_info('--- End CAS flow ---')

    self.add_menu() 

    self.send_page()
