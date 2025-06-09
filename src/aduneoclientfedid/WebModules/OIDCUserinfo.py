"""
Copyright 2024 Aduneo

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
import json
import traceback
import urllib.parse

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..Configuration import Configuration
from ..Explanation import Explanation
from ..Help import Help
from ..CfiForm import RequesterForm
from .FlowHandler import FlowHandler

"""
  Récupération userinfo dans une cinématique OpenID Connect

  Utilise les éléments du contexte et les mets à jour en fonction des saisies de l'utilisateur
"""


@register_web_module('/client/oidc/userinfo')
class OIDCUserinfo(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête userinfo

      Propose le jeton d'identité courant (le dernier obtenu par défaut) avec possibilité d'en changer

      La requête est transmise à sendrequest pour exécution
    
    Versions:
      08/08/2024 (mpham) version initiale
      29/05/2025 (mpham) adaptation à la nouvelle structure de idp_params
      08/06/2025 (mpham) DNS override
    """
    
    try:

      self.log_info('Userinfo flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      idp_params = self.context.idp_params
      oidc_idp_params = idp_params.get('oidc')
      if not oidc_idp_params:
        raise AduneoError(f"OIDC IdP configuration missing for {idp_params.get('name', self.context.idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={self.context.idp_id}")
      app_params = self.context.last_app_params

      access_tokens = {}
      default_access_token = None
      for token_wrapper_key in sorted(self.context['id_tokens'].keys(), reverse=True):
        token_wrapper = self.context['id_tokens'][token_wrapper_key]
        if 'access_token' in token_wrapper:
          access_tokens[token_wrapper['access_token']] = token_wrapper['name']
          if not default_access_token:
              default_access_token = token_wrapper['access_token']

      form_content = {
        'contextid': self.context['context_id'],
        'userinfo_endpoint': oidc_idp_params.get('userinfo_endpoint', ''),
        'access_token': default_access_token,
        'userinfo_method': oidc_idp_params.get('userinfo_method', 'get'),
        'userinfo_endpoint_dns_override': oidc_idp_params.get('userinfo_endpoint_dns_override', ''),
      }
      form = RequesterForm('userinfo', form_content, action='/client/oidc/userinfo/sendrequest', request_url='@[userinfo_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint') \
        .closed_list('access_token', label='Access Token', 
          values = access_tokens,
          default = default_access_token
          ) \
        .closed_list('userinfo_method', label='Userinfo Request Method', 
          values={'get': 'GET', 'post': 'POST'},
          default = 'get'
          ) \
        .text('userinfo_endpoint_dns_override', label='Userinfo endpoint DNS override', clipboard_category='userinfo_endpoint_dns_override') \
        
      form.set_title('User Info '+idp_params['name'])
      form.set_request_parameters(None)
      form.modify_http_parameters({
        'request_url': '@[userinfo_endpoint]',
        'form_method': '@[userinfo_method]',
        'auth_method': 'bearer_token',
        'auth_login': '@[access_token]',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        'dns_override': '@[userinfo_endpoint_dns_override]',
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': False,
        'form_method': True,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_option('/requester/cancel_button', '/client/flows/cancelrequest?contextid='+urllib.parse.quote(self.context.context_id))

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())
      self.send_page()
          
    except AduneoError as error:
      self.add_html('<h4>Userinfo error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Userinfo error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()


  @register_page_url(url='sendrequest', method='POST', continuous=True)
  def send_request(self):
    """ Effectue la requête userinfo et l'affiche

    Versions:
      08/08/2024 (mpham) version initiale
      29/05/2025 (mpham) adaptation à la nouvelle structure de idp_params
      08/06/2025 (mpham) DNS override
    """
    
    #self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre>')

    if self.context:
    
      # Mise à jour de la requête en cours
      idp_params = self.context.idp_params
      oidc_idp_params = idp_params.get('oidc')
      if not oidc_idp_params:
        raise AduneoError(f"OIDC IdP configuration missing for {idp_params.get('name', idp_id)}")
      for item in ['userinfo_endpoint', 'userinfo_method', 'userinfo_endpoint_dns_override']:
        oidc_idp_params[item] = self.post_form.get(item, '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'
    
    try:
      response = RequesterForm.send_form(self, self.post_form)
      json_response = response.json()
      
      self.start_result_table()
      self.log_info('Userinfo response'+json.dumps(json_response, indent=2))
      self.add_result_row('Userinfo response', json.dumps(json_response, indent=2), 'userinfo_response', expanded=True)
      self.end_result_table()
      
    except Exception as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à userinfo : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

