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
  Révocation de jeton d'accès (RFC 7009)

  Utilise les éléments du contexte et les met à jour en fonction des saisies de l'utilisateur
"""


@register_web_module('/client/oauth2/revocation')
class OAuth2Revocation(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête de révocation

      Propose le jeton d'accès courant (le dernier obtenu par défaut) avec possibilité d'en changer
        Ainsi que les jetons d'accès récupérés dans des cinématiques OIDC

      La requête est transmise à sendrequest pour exécution
    
    Versions:
      07/06/2025 (mpham) version initiale adaptée de introspection
    """
    
    try:

      self.log_info('Revocation flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params.get('oauth2')
      if not oauth2_idp_params:
        raise AduneoError(f"OAuth 2 IdP configuration missing for {idp_params.get('name', self.context.idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={self.context.idp_id}")
      app_params = self.context.last_app_params

      # Jetons d'accès et de rafraîchissement
      token_wrappers = {}     # avec le type
      display_tokens = {'__input__': 'Direct Input'}     # clé jeton, valeur non pour le select
      default_token = None
      default_wrapper = None
      all_access_tokens = self.context.get_all_access_tokens()
      for token_wrapper_key in sorted(all_access_tokens.keys(), reverse=True):
        token_wrapper = all_access_tokens[token_wrapper_key]
        token_wrapper['token_type_hint'] = 'access_token'
        token_wrappers[token_wrapper['access_token']] = token_wrapper
        display_tokens[token_wrapper['access_token']] = token_wrapper['name']
        if not default_token:
          default_token = token_wrapper['access_token'] 
          default_wrapper = token_wrapper 
        if token_wrapper.get('refresh_token'):
          refresh_token = token_wrapper['refresh_token']
          token_wrapper = {'name': 'refresh for '+token_wrapper['name'], 'token_type_hint': 'refresh_token'}
          token_wrappers[refresh_token] = token_wrapper
          display_tokens[refresh_token] = token_wrapper['name']
          if not default_token:
            default_token = refresh_token 
            default_wrapper = token_wrapper 

      form_content = {
        'contextid': self.context['context_id'],
        'revocation_endpoint': oauth2_idp_params.get('revocation_endpoint', ''),
        'tokens': default_token,
        'token': default_token if default_token != '__input__' else '',
        'token_type_hint': default_wrapper['token_type_hint'] if default_token != '__input__' else '',
        'revocation_auth_method': oauth2_idp_params.get('revocation_auth_method', 'basic'),
        'client_id': app_params.get('client_id', ''),
        'revocation_endpoint_dns_override': oauth2_idp_params.get('revocation_endpoint_dns_override', ''),
      }
      form = RequesterForm('revocation', form_content, action='/client/oauth2/revocation/sendrequest', request_url='@[revocation_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('revocation_endpoint', label='Revocation endpoint', clipboard_category='revocation_endpoint') \
        .closed_list('tokens', label='Select token', 
          values = display_tokens,
          default = default_token,
          on_change = """let value = cfiForm.getThisFieldValue();
            if (value != '__input__') {
              cfiForm.setFieldValue('token', value);
              cfiForm.setFieldValue('token_type_hint', cfiForm.getTable('token_wrappers')[value]['token_type_hint']);
            }
            """,
          ) \
        .textarea('token', label='Token', clipboard_category='token', displayed_when="@[tokens] = '__input__'") \
        .closed_list('token_type_hint', label='Token type hint', 
          values = {'': '', 'access_token': 'access_token', 'refresh_token': 'refresh_token'},
          default = '',
          ) \
        .closed_list('revocation_auth_method', label='Revocation authn. method', 
          values = {'none': 'None', 'basic': 'Basic'},
          default = 'basic'
          ) \
        .text('client_id', label='Client ID', clipboard_category='client_id', displayed_when="@[revocation_auth_method] = 'basic'") \
        .password('client_secret', label='Secret', clipboard_category='client_secret!', displayed_when="@[revocation_auth_method] = 'basic'") \
        .text('revocation_endpoint_dns_override', label='Revocation endpoint DNS override', clipboard_category='revocation_endpoint_dns_override') \
        
      form.set_title('Revocation '+idp_params['name'])
      form.set_table('token_wrappers', token_wrappers)
      form.set_request_parameters({
        'token': '@[token]',
      })
      form.modify_http_parameters({
        'request_url': '@[revocation_endpoint]',
        'form_method': 'post',
        'auth_method': '@[revocation_auth_method]',
        'auth_login': '@[client_id]',
        'auth_secret': '@[client_secret]',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        'dns_override': '@[revocation_endpoint_dns_override]',
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'form_method': False,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_option('/clipboard/remember_secrets', True)
      form.set_option('/requester/auth_method_options', ['none', 'basic'])
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
    """ Effectue la requête de révocation et l'affiche

    Versions:
      07/06/2025 (mpham) version initiale adaptée de introspection
    """
    
    #self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre>')

    try:

      if not self.context:
        raise AduneoError("Context not found in session")
      
      # Mise à jour de la requête en cours
      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      for item in ['revocation_endpoint', 'revocation_auth_method', 'revocation_endpoint_dns_override']:
        oauth2_idp_params[item] = self.post_form.get(item, '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'

      # on récupére le client_secret
      if self.post_form.get('revocation_auth_method') in ['basic']:
        client_secret = self.post_form.get('client_secret', '')
        app_params = self.context.last_app_params
        if client_secret != '':
          app_params['client_secret'] = client_secret
        else:
          app_params = self.context.last_app_params
          client_secret = app_params.get('client_secret', '')
        if client_secret == '':
          conf_idp = self.conf['idps'][self.context.idp_id]
          conf_app = conf_idp['oauth2_clients'][self.context.app_id]
          client_secret = conf_app.get('client_secret!', '')
    
      response = RequesterForm.send_form(self, self.post_form, default_secret=client_secret)
      
      self.start_result_table()
      self.log_info('Revocation response: '+str(response.status))
      self.add_result_row('Revocation response', str(response.status), 'revocation_response', expanded=True)
      self.end_result_table()
      
      # on note le jeton comme révoqué dans le contexte
      if response.status == 200:
        for acces_token_wrapper in self.context['access_tokens'].values():
          if acces_token_wrapper.get('access_token') == self.post_form['token'] or acces_token_wrapper.get('refresh_token') == self.post_form['token']:
            acces_token_wrapper['name'] = 'REVOKED - ' + acces_token_wrapper['name']
      
    except AduneoError as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à revocation : {error}""".format(error=html.escape(str(error))))
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html("""<div class="intertable">Erreur lors de l'appel à revocation : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

