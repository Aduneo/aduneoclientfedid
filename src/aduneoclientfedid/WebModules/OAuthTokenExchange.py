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
import time
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
  Echange de jeton Token Exchange (RFC 8693)

  Utilise les éléments du contexte
"""


@register_web_module('/client/oauth2/tokenexchange')
class OAuth2TokenExchange(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête d'échange de jeton

      La requête est transmise à sendrequest pour exécution
    
    Versions:
      25/02/2025 (mpham) version initiale adaptée de OAuthClientLogin.token_exchange_spa
    """
    
    try:

      self.log_info('Token Exchange flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      self.log_info(('  ' * 1)+'IdP: '+idp_params['name'])

      # Jetons
      token_params = {'0': {'name': 'Type token'}}
      token_select = {'0': 'Manually type token'}
      default_wrapper = None
      i = 1
      for wrapper in sorted(self.context.get_all_tokens(), key=lambda item: item['timestamp'], reverse=True):
        
        if wrapper['type'] != 'saml_assertion':
        
          token_params[str(i)] = wrapper
          token_select[str(i)] = wrapper['name']
          wrapper['type'] = {
            'id_token': 'urn:ietf:params:oauth:token-type:id_token', 
            'access_token': 'urn:ietf:params:oauth:token-type:access_token', 
            'refresh_token': 'urn:ietf:params:oauth:token-type:refresh_token', 
            'saml_assertion': 'urn:ietf:params:oauth:token-type:saml2'
            }[wrapper['type']]
          app_params = self.context.app_params.get(wrapper['app_id'])
          wrapper['client_id'] = app_params['client_id'] if app_params else ''
          
          if i == 1:
            default_wrapper = wrapper
          i += 1

      form_content = {
        'contextid': self.context['context_id'],
        'token_endpoint': oauth2_idp_params.get('token_endpoint', ''),
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'resource': '',
        'audience': '',
        'scope': '',
        'requested_token_type': '',
        'token_select': '1' if default_wrapper else '0',
        'subject_token': default_wrapper['token'] if default_wrapper else '',
        'subject_token_type': default_wrapper['type'] if default_wrapper else '',
        'token_name': default_wrapper['name'] if default_wrapper else '',
        'client_id': default_wrapper['client_id'] if default_wrapper else '',
        'app_id': default_wrapper['app_id'] if default_wrapper else '',
        'client_secret': '',
        'actor_token': '',
        'actor_token_type': '',
      }
      form = RequesterForm('tokenexchange', form_content, action='/client/oauth2/tokenexchange/sendrequest', request_url='@[token_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint') \
        .text('grant_type', label='Grant type', clipboard_category='grant_type') \
        .closed_list('token_select', label='Token', 
          values = token_select,
          default = '1' if default_wrapper else '0',
          on_change = """let tokenIndex = cfiForm.getThisFieldValue(); 
            if (tokenIndex != '0') {
              cfiForm.setFieldValue('subject_token', cfiForm.getTable('token_params')[tokenIndex]['token']);
              cfiForm.setFieldValue('subject_token_type', cfiForm.getTable('token_params')[tokenIndex]['type']);
              cfiForm.setFieldValue('app_id', cfiForm.getTable('token_params')[tokenIndex]['app_id']);
              cfiForm.setFieldValue('token_name', cfiForm.getTable('token_params')[tokenIndex]['name']);
              cfiForm.setFieldValue('client_id', cfiForm.getTable('token_params')[tokenIndex]['client_id']);
            }
            """,
          ) \
        .text('subject_token', label='Subject token', clipboard_category='subject_token', displayed_when="@[token_select] = '0'") \
        .text('subject_token_type', label='Subject token type', clipboard_category='subject_token_type') \
        .open_list('requested_token_type', label='Requested token type', 
          hints = [
            'urn:ietf:params:oauth:token-type:id_token',
            'urn:ietf:params:oauth:token-type:access_token', 
            'urn:ietf:params:oauth:token-type:refresh_token', 
            ]) \
        .text('resource', label='Resource', clipboard_category='resource') \
        .text('audience', label='Audience', clipboard_category='audience') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .text('actor_token', label='Actor token', clipboard_category='actor_token') \
        .text('actor_token_type', label='Actor token type', clipboard_category='actor_token_type') \
        .closed_list('auth_method', label='Authn. Method', 
          values = {'none': 'None', 'basic': 'Basic', 'form': 'Form'},
          default = 'basic'
          ) \
        .hidden('app_id') \
        .hidden('token_name') \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .password('client_secret', label='Client secret', clipboard_category='client_secret') \
        
      form.set_title('Token Exchange '+idp_params['name'])
      form.set_table('token_params', token_params)
      form.set_request_parameters({
        'grant_type': '@[grant_type]',
        'subject_token': '@[subject_token]',
        'subject_token_type': '@[subject_token_type]',
        'requested_token_type': '@[requested_token_type]',
        'resource': '@[resource]',
        'audience': '@[audience]',
        'scope': '@[scope]',
        'actor_token': '@[actor_token]',
        'actor_token_type': '@[actor_token_type]',
      })
      form.modify_http_parameters({
        'request_url': '@[token_endpoint]',
        'auth_method': '@[auth_method]',
        'auth_login': '@[client_id]',
        'auth_secret': '@[client_secret]',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'form_method': True,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_data_generator_code("""
        if (cfiForm.getField('auth_method').value == 'form') {
          paramValues['client_id'] = cfiForm.getField('client_id').value;
        }
        return paramValues;
      """)
      form.set_option('/clipboard/remember_secrets', True)
      form.set_option('/requester/auth_method_options', ['none', 'basic', 'bearer_token'])
      form.set_option('/requester/cancel_button', '/client/flows/cancelrequest?contextid='+urllib.parse.quote(self.context.context_id))
      form.set_option('/requester/include_empty_items', False)

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())
      self.send_page()
          
    except AduneoError as error:
      self.add_html('<h4>Token exchange error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Token exchange error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()


  @register_page_url(url='sendrequest', method='POST', continuous=True)
  def send_request(self):
    """ Effectue la requête d'échange de jeton et l'affiche

    Versions:
      25/02/2025 (mpham) version initiale adaptée de OAuthClientLogin.token_exchange_spa
    """
    
    #self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre>')
    self.add_html("""<h2>Token exchange response</h2>""")

    try:

      if not self.context:
        raise AduneoError("Context not found in session")

      # récupération du secret
      client_secret = self.post_form.get('client_secret', '')
      if client_secret == '':
        # on commence par aller chercher le secret dans le contexte
        app_id = self.post_form.get('app_id')
        if app_id:
          app_params = self.context.app_params.get(app_id)
          client_secret = app_params.get('client_secret')
          if client_secret is None:
            # on va maintenant le chercher dans la configuration
            conf_idp = self.conf['idps'][self.context.idp_id]
            conf_app = conf_idp['oauth2_clients'][app_id]
            client_secret = conf_app.get('client_secret!', '')
    
      response = RequesterForm.send_form(self, self.post_form, default_secret=client_secret)
      json_response = response.json()
      
      self.start_result_table()
      self.log_info('Token exchange response'+json.dumps(json_response, indent=2))
      self.add_result_row('Token exchange response', json.dumps(json_response, indent=2), 'token_exchange_response', expanded=True)
      self.end_result_table()
      
      if response.status_code == 200:

        token_name = 'Exchange from '+self.post_form.get('token_name', '?')+' - '+time.strftime("%H:%M:%S", time.localtime())
        token = {'name': token_name, 'app_id': self.post_form.get('app_id')}
        
        if json_response.get('issued_token_type') == 'urn:ietf:params:oauth:token-type:id_token':
          token['type'] = 'id_token'
          token['id_token'] = json_response.get('access_token')
          self.context['id_tokens'][str(time.time())] = token
        elif json_response.get('issued_token_type') == 'urn:ietf:params:oauth:token-type:access_token':
          token['type'] = 'access_token'
          token['access_token'] = json_response.get('access_token')
          self.context['access_tokens'][str(time.time())] = token
        elif json_response.get('issued_token_type') == 'urn:ietf:params:oauth:token-type:refresh_token':
          token['type'] = 'refresh_token'
          token['refresh_token'] = json_response.get('access_token')
          self.context['access_tokens'][str(time.time())] = token
      
    except AduneoError as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à Token exchange : {error}""".format(error=html.escape(str(error))))
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html("""<div class="intertable">Erreur lors de l'appel à Token exchange : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

