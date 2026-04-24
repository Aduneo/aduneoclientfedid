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
from ..WebRequest import WebRequest

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
      # Needed : 'userinfo_endpoint', 'userinfo_method', 'userinfo_endpoint_dns_override'
      # Condition pour récupérer userinfo_endpoint dans une cinématique OAuth --> OIDC --> userinfo
      # Il faut prendre les paramètres OAuth pour récupérer 'userinfo_endpoint'
      oidc_idp_params = idp_params.get('oidc', {})
      fetch_configuration_document = False

      # Cas par défaut : on prend les paramètres OIDC si ils existent
      if 'userinfo_endpoint' in oidc_idp_params:
        self.log_info("Using OIDC IDP parameters for userinfo_endpoint")
      # Sinon on cherche dans les paramètres OAuth actualisés
      elif 'userinfo_endpoint' in idp_params.get('oauth2', {}):
        oidc_idp_params = idp_params['oauth2']
        self.log_info("Using OAuth IDP parameters as substitute for userinfo_endpoint")
      # Sinon on essaie de récupérer les infos en discovery
      elif oidc_idp_params.get('endpoint_configuration', 'local_configuration') != 'local_configuration':
        if oidc_idp_params.get('endpoint_configuration', '') == 'same_as_oauth2':
          # récupération des paramètres OIDC pour les endpoints
          oauth2_params = idp_params.get('oauth2')
          if not oauth2_params:
            raise AduneoError("can't retrieve endpoint parameters from OAuth 2 configuration since OAuth 2 is not configured")
          if oauth2_params.get('endpoint_configuration') == 'same_as_oidc':
            raise AduneoError("can't retrieve endpoint parameters from OAuth 2 configuration since OAuth 2 is configured with same_as_oidc")
          for param in ['endpoint_configuration', 'metadata_uri']:
            oidc_idp_params[param] = oauth2_params.get(param, '')
          if oidc_idp_params.get('endpoint_configuration') == 'metadata_uri':
            oidc_idp_params['endpoint_configuration'] = 'discovery_uri'
            oidc_idp_params['discovery_uri'] = oauth2_params.get('metadata_uri')
        if oidc_idp_params.get('endpoint_configuration', '') == 'discovery_uri':
          fetch_configuration_document = True
          self.log_info("Fetching OIDC IDP parameters for userinfo_endpoint")
      
      if fetch_configuration_document:
        self.add_html("""<div class="intertable">Fetching IdP configuration document from {url}</div>""".format(url=oidc_idp_params['discovery_uri']))
        try:
          self.log_info('Starting metadata retrieval')
          self.log_info('discovery_uri: '+oidc_idp_params['discovery_uri'])
          verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
          self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
          r = WebRequest.get(oidc_idp_params['discovery_uri'], verify_certificate=verify_certificates)
          self.log_info(r.data)
          meta_data = r.json()
          oidc_idp_params.update(meta_data)
          self.add_html("""<div class="intertable">Success</div>""")
        except Exception as error:
          self.log_error(traceback.format_exc())
          self.add_html(f"""<div class="intertable">Failed: {error}</div>""")
          self.send_page()
          return
        if r.status != 200:
          self.log_error('Server responded with code '+str(r.status))
          self.add_html(f"""<div class="intertable">Failed. Server responded with code {r.status}</div>""")
          self.send_page()
          return
      
      if 'userinfo_endpoint' not in oidc_idp_params: 
        self.add_html('<h4>No userinfo endpoint scheme in either OIDC or OAuth idp_params</h4>')
      
      # app_params = self.context.last_app_params

      access_tokens = {}
      default_access_token = None
      for token_wrapper_key in sorted(self.context['id_tokens'].keys(), reverse=True):
        token_wrapper = self.context['id_tokens'][token_wrapper_key]
        if 'access_token' in token_wrapper:
          access_tokens[token_wrapper['access_token']] = token_wrapper['name']
          if not default_access_token:
              default_access_token = token_wrapper['access_token']

      form_id = 'userinfo'
      form_content = {
        'form_id' : form_id,
        'contextid': self.context['context_id'],
        'userinfo_endpoint': oidc_idp_params.get('userinfo_endpoint', ''),
        'access_token': default_access_token,
        'userinfo_method': oidc_idp_params.get('userinfo_method', 'get'),
        'userinfo_endpoint_dns_override': oidc_idp_params.get('userinfo_endpoint_dns_override', ''),
      }
      form = RequesterForm(form_id, form_content, action='/client/oidc/userinfo/sendrequest', request_url='@[userinfo_endpoint]', mode='api') \
        .hidden('form_id') \
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
        raise AduneoError(f"OIDC IdP configuration missing for {idp_params.get('name', default='[Could not fetch name]')}")
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
      form_id = self.post_form.get('form_id')
      self.add_result_row('Userinfo response', json.dumps(json_response, indent=2), form_id, 'userinfo_response', expanded=True)
      self.end_result_table()
      
    except Exception as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à userinfo : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

