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
  Validation de jeton d'accès par introspection (RFC 7662)

  Utilise les éléments du contexte et les met à jour en fonction des saisies de l'utilisateur
"""


@register_web_module('/client/oauth2/introspection')
class OAuth2Introspection(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête d'introspection

      Propose le jeton d'accès courant (le dernier obtenu par défaut) avec possibilité d'en changer
        Ainsi que les jetons d'accès récupérés dans des cinématiques OIDC

      La requête est transmise à sendrequest pour exécution
    
    Versions:
      28/08/2024 (mpham) version initiale adaptée de userinfo
      29/12/2025 (mpham) les méthodes HTTP et Authn peuvent être héritées de celles définis auprès de l'IdP
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
      05/06/2025 (mpham) DNS override
    """
    
    try:

      self.log_info('Introspection flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params.get('oauth2')
      if not oauth2_idp_params:
        raise AduneoError(f"OAuth 2 IdP configuration missing for {idp_params.get('name', self.context.idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={self.context.idp_id}")
      app_params = self.context.last_app_params
      api_params = self.context.last_api_params

      # API réalisant l'introspection
      idp_id = self.context.idp_id
      conf_idp = self.conf['idps'][idp_id]
      api_values = {'__input__': 'Direct Input'}
      
      on_api_change = "let apis = [];"
      for api_id in conf_idp.get('oauth2_apis', []):
        conf_api = conf_idp['oauth2_apis'][api_id]
        api_values[api_id] = conf_api['name']
        
        introspection_http_method = conf_api.get('introspection_http_method', 'post')
        if introspection_http_method == 'inherit_from_idp':
          introspection_http_method = conf_idp.get('introspection_http_method', 'post')
          
        introspection_auth_method = conf_api.get('introspection_auth_method', 'basic')
        if introspection_auth_method == 'inherit_from_idp':
          introspection_auth_method = conf_idp.get('introspection_auth_method', 'basic')
          
        on_api_change += "apis['"+api_id+"'] = {login: '"+self.escape_string_to_javascript(conf_api['login'])+"', http_method: '"+introspection_http_method+"', auth_method: '"+introspection_auth_method+"'};"
      on_api_change += """if (cfiForm.getThisFieldValue() != '__input__') { 
        cfiForm.setFieldValue('introspection_login', apis[cfiForm.getThisFieldValue()].login); 
        cfiForm.setFieldValue('introspection_http_method', apis[cfiForm.getThisFieldValue()].http_method); 
        cfiForm.setFieldValue('introspection_auth_method', apis[cfiForm.getThisFieldValue()].auth_method); 
      }"""

      # Jetons d'accès
      access_tokens = {}
      default_access_token = None
      all_access_tokens = self.context.get_all_access_tokens()
      for token_wrapper_key in sorted(all_access_tokens.keys(), reverse=True):
        token_wrapper = all_access_tokens[token_wrapper_key]
        access_tokens[token_wrapper['access_token']] = token_wrapper['name']
        if not default_access_token:
            default_access_token = token_wrapper['access_token']  

      form_content = {
        'contextid': self.context['context_id'],
        'introspection_endpoint': oauth2_idp_params.get('introspection_endpoint', ''),
        'access_token': default_access_token,
        'introspection_http_method': api_params.get('introspection_http_method', oauth2_idp_params.get('introspection_http_method', 'post')),
        'introspection_auth_method': api_params.get('introspection_auth_method', oauth2_idp_params.get('introspection_auth_method', 'basic')),
        'introspection_api': api_params.get('introspection_api', '__input__'),
        'introspection_login': api_params.get('introspection_login', ''),
        'introspection_secret': '',
        'introspection_endpoint_dns_override': oauth2_idp_params.get('introspection_endpoint_dns_override', ''),
      }
      form = RequesterForm('introspection', form_content, action='/client/oauth2/introspection/sendrequest', request_url='@[introspection_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint') \
        .closed_list('access_token', label='Access Token', 
          values = access_tokens,
          default = default_access_token
          ) \
        .closed_list('introspection_api', label='API initiating introspection', 
          values = api_values,
          default = '__input__',
          on_change = on_api_change,
          ) \
        .closed_list('introspection_http_method', label='Introspect. Request Method', displayed_when="@[introspection_api] = '__input__'",
          values = {'get': 'GET', 'post': 'POST'},
          default = 'post'
          ) \
        .closed_list('introspection_auth_method', label='Introspect. Authn. Method', displayed_when="@[introspection_api] = '__input__'", 
          values = {'none': 'None', 'basic': 'Basic', 'bearer_token': 'Bearer Token'},
          default = 'basic'
          ) \
        .text('introspection_login', label='Login', clipboard_category='client_id', displayed_when="@[introspection_api] = '__input__' and (@[introspection_auth_method] = 'basic' or @[introspection_auth_method] = 'bearer_token')") \
        .password('introspection_secret', label='Secret', clipboard_category='client_secret!', displayed_when="@[introspection_api] = '__input__' and @[introspection_auth_method] = 'basic'") \
        .text('introspection_endpoint_dns_override', label='Introspection endpoint DNS override', clipboard_category='introspection_endpoint_dns_override') \
        
      form.set_title('Introspection '+idp_params['name'])
      form.set_request_parameters({
        'token': '@[access_token]',
      })
      form.modify_http_parameters({
        'request_url': '@[introspection_endpoint]',
        'form_method': '@[introspection_http_method]',
        'auth_method': '@[introspection_auth_method]',
        'auth_login': '@[introspection_login]',
        'auth_secret': '@[introspection_secret]',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        'dns_override': '@[introspection_endpoint_dns_override]',
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'form_method': True,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_option('/clipboard/remember_secrets', True)
      form.set_option('/requester/auth_method_options', ['none', 'basic', 'bearer_token'])
      form.set_option('/requester/cancel_button', '/client/flows/cancelrequest?contextid='+urllib.parse.quote(self.context.context_id))

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())
      self.send_page()
          
    except AduneoError as error:
      self.add_html('<h4>Introspection error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Introspection error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()


  @register_page_url(url='sendrequest', method='POST', continuous=True)
  def send_request(self):
    """ Effectue la requête d'introspection et l'affiche

    Versions:
      04/09/2024 (mpham) version initiale adaptée de userinfo
      27/02/2025 (mpham) les paramètres IdP n'étaient pas mis à jour au bon endroit
      05/06/2025 (mpham) DNS override
    """
    
    #self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre>')

    try:

      if not self.context:
        raise AduneoError("Context not found in session")
      
      # Mise à jour de la requête en cours
      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      for item in ['introspection_endpoint', 'introspection_endpoint_dns_override']:
        oauth2_idp_params[item] = self.post_form.get(item, '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'
    
      # Si on est en mode manuel, on conserve les paramètres en question
      introspection_secret = None
      if self.post_form['introspection_api'] == '__input__':
        api_params = self.context.last_api_params
        for item in ['introspection_http_method', 'introspection_auth_method', 'introspection_login']:
          api_params[item] = self.post_form.get(item, '')
          
        if self.post_form.get('introspection_secret', '') == '':
          introspection_secret = api_params.get('introspection_secret', '')
        else:
          api_params['introspection_secret'] = self.post_form['introspection_secret']
          
      else:
        # on va chercher le secret dans la configuration
        conf_idp = self.conf['idps'][self.context.idp_id]
        conf_api = conf_idp['oauth2_apis'][self.post_form['introspection_api']]
        introspection_secret = conf_api.get('secret!', '')
    
      response = RequesterForm.send_form(self, self.post_form, default_secret=introspection_secret)
      json_response = response.json()
      
      self.start_result_table()
      self.log_info('Introspection response'+json.dumps(json_response, indent=2))
      self.add_result_row('Introspection response', json.dumps(json_response, indent=2), 'introspection_response', expanded=True)
      self.end_result_table()
      
    except AduneoError as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à introspection : {error}""".format(error=html.escape(str(error))))
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html("""<div class="intertable">Erreur lors de l'appel à introspection : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

