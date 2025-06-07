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
import time
import traceback
import urllib.parse

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import RequesterForm
from ..Configuration import Configuration
from ..Explanation import Explanation
from ..Help import Help
from .FlowHandler import FlowHandler
from .OAuthClientLogin import OAuthClientLogin
"""
  Rafraîchissement d'un jeton d'accès (RFC 6749)

  Utilise les éléments du contexte et les mets à jour en fonction des saisies de l'utilisateur
  
  TODO: on doit pouvoir lancer un refresh sans authentification préalable (depuis la page d'accueil donc), en fournissant un AT)
"""


@register_web_module('/client/oauth2/refresh')
class OAuth2Refresh(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête de rafraîchissement d'un jeton d'accès

      Propose le jeton d'accès courant (le dernier obtenu par défaut) avec possibilité d'en changer
        Ainsi que les jetons d'accès récupérés dans des cinématiques OIDC

      La requête est transmise à sendrequest pour exécution
    
      Versions:
        03/12/2024 (mpham) version initiale adaptée de introspection
        31/12/2024 (mpham) rafraîchissement des AT issus d'OIDC
    """
    
    try:

      self.log_info('Refresh flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      conf_idp = self.conf['idps'][self.context.idp_id]
      
      conf_apps = dict(conf_idp.get('oauth2_clients', {}))
      conf_apps.update(conf_idp.get('oidc_clients', {}))

      idp_params = self.context.idp_params
      all_app_params = self.context.app_params

      # Jetons de rafraîchissement et clients associés
      refresh_tokens = {'__input__': 'Direct Input'}    # clé : RT, valeur : nom d'affichage
      token_clients = {'__input__': ''}    # clé : RT, valeur : app_id
      default_refresh_token = '__input__'
      default_app_id = None
      all_access_tokens = self.context.get_all_access_tokens()
      for token_wrapper_key in sorted(all_access_tokens.keys(), reverse=True):
        token_wrapper = all_access_tokens[token_wrapper_key]
        if token_wrapper.get('refresh_token'):
          refresh_tokens[token_wrapper['refresh_token']] = token_wrapper['name']
          token_clients[token_wrapper['refresh_token']] = token_wrapper['app_id']
          if default_refresh_token == '__input__':
            default_refresh_token = token_wrapper['refresh_token']
            default_app_id = token_wrapper['app_id']

      # Récupération des client ID et des méthodes d'authentification
      client_ids = {'__input__': 'Direct input'}   # clé : app_id, valeur : client_id
      token_endpoint_auth_methods = {}   # clé : app_id, valeur : none/client_secret_basic/client_secret_post
      for app_id in token_clients.values():
        if not client_ids.get(app_id):
          conf_app = conf_apps.get(app_id)
          if conf_app:
              client_ids[app_id] = conf_app['client_id']
              token_endpoint_auth_methods[app_id] = {'none': 'none', 'client_secret_basic': 'basic', 'client_secret_post': 'form'}.get(conf_app.get('token_endpoint_auth_methods', 'client_secret_basic'), 'client_secret_basic')

      form_content = {
        'contextid': self.context['context_id'],
        'token_endpoint': idp_params.get('token_endpoint', ''),
        'refresh_tokens': default_refresh_token,
        'refresh_token': default_refresh_token if default_refresh_token != '__input__' else '',
        'grant_type': 'refresh_token',
        'scope': '',
        'client_ids': default_app_id,
        'client_id': client_ids[default_app_id],
        'token_endpoint_auth_method': token_endpoint_auth_methods[default_app_id],
      }
      form = RequesterForm('refresh', form_content, action='/client/oauth2/refresh/sendrequest', request_url='@[token_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint') \
        .closed_list('refresh_tokens', label='Select refresh token', 
          values = refresh_tokens,
          default = default_refresh_token,
          on_change = """let value = cfiForm.getThisFieldValue();
            if (value != '__input__') {
              cfiForm.setFieldValue('refresh_token', value);
              cfiForm.setFieldValue('clients', cfiForm.getTable('token_clients')[value]);
            }
            """,
          ) \
        .textarea('refresh_token', label='Refresh token', clipboard_category='refresh_token', displayed_when="@[refresh_tokens] = '__input__'") \
        .text('grant_type', label='Grant type', clipboard_category='grant_type') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('client_ids', label='Select client', 
          values = client_ids,
          default = default_app_id,
          on_change = """let value = cfiForm.getThisFieldValue();
            if (value != '__input__') {
              cfiForm.setFieldValue('token_endpoint_auth_method', cfiForm.getTable('token_endpoint_auth_methods')[value]);
              cfiForm.setFieldValue('client_id', cfiForm.getTable('client_ids')[value]);
              cfiForm.setFieldValue('client_secret', '');
            }
            """,
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', displayed_when="@[client_ids] = '__input__'", 
          values={'none': 'none', 'basic': 'client_secret_basic', 'form': 'client_secret_post'},
          default = 'basic'
          ) \
        .text('client_id', label='Client ID', clipboard_category='client_id', displayed_when="@[client_ids] = '__input__'") \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[client_ids] = '__input__'") \
        
      form.set_title('Refresh '+idp_params['name'])
      form.set_table('token_clients', token_clients)
      form.set_request_parameters({
        'refresh_token': '@[refresh_token]',
        'grant_type': '@[grant_type]',
        'scope': '@[scope]',
      })
      form.modify_http_parameters({
        'request_url': '@[token_endpoint]',
        'form_method': 'post',
        'body_format': 'x-www-form-urlencoded',
        'auth_method': '@[token_endpoint_auth_method]',
        'auth_login': '@[client_id]',
        'auth_secret': '@[client_secret]',
        'hr_auth_login_param': 'client_id',
        'hr_auth_secret_param': 'client_secret',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'body_format': False,
        'form_method': False,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_option('/clipboard/remember_secrets', True)
      form.set_option('/requester/cancel_button', '/client/flows/cancelrequest?contextid='+urllib.parse.quote(self.context.context_id))
      form.set_option('/requester/include_empty_items', False)

      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())
      self.send_page()
          
    except AduneoError as error:
      self.add_html('<h4>Refresh error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Refresh error: '+html.escape(str(error))+'</h4>')
      self.add_menu()
      self.send_page()


  @register_page_url(url='sendrequest', method='POST', continuous=True)
  def send_request(self):
    """ Effectue la requête de rachaîchissement de jeton d'accès

      Versions:
        03/12/2024 (mpham) version initiale adaptée de introspection
        31/12/2024 (mpham) rafraîchissement des AT issus d'OIDC
    """
    
    try:

      if not self.context:
        raise AduneoError("Context not found in session")
      
      # Mise à jour de la requête en cours
      idp_params = self.context.idp_params
      for item in ['token_endpoint']:
        idp_params[item] = self.post_form.get(item, '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'
    
      conf_idp = self.conf['idps'][self.context.idp_id]
      conf_apps = dict(conf_idp.get('oauth2_clients', {}))
      conf_apps.update(conf_idp.get('oidc_clients', {}))
      app_id = self.post_form['client_ids']
    
      # On obtient le secret
      client_secret = None
      if app_id != '__input__':
        client_secret = conf_apps[self.post_form['client_ids']].get('client_secret!', '')
    
      response = RequesterForm.send_form(self, self.post_form, default_secret=client_secret)
      json_response = response.json()
      
      self.start_result_table()
      self.log_info('Refresh response'+json.dumps(json_response, indent=2))
      self.add_result_row('Refresh response', json.dumps(json_response, indent=2), 'refresh_response', expanded=False)
      
      new_access_token = json_response.get('access_token')
      new_refresh_token = json_response.get('refresh_token')
      OAuthClientLogin.display_tokens(self, new_access_token, new_refresh_token, idp_params, client_secret)

      if (new_access_token):
        
        if app_id != '__input__':
          # on met à jour le contexte, on ajoute (refreshed) au nom du jeton et on ajoute le nouveau jeton aux jetons d'accès
          old_refresh_token = self.post_form['refresh_token']
          for token_type in ['id_tokens', 'access_tokens']:
            for timestamp in self.context[token_type]:
              token_wrapper = self.context[token_type][timestamp]
              if token_wrapper.get('refresh_token') == old_refresh_token:
                name = token_wrapper['name']
                if name.find('(refreshed') == -1:
                  token_wrapper['name'] = name + ' (refreshed)'
                  
          app_params = conf_apps[app_id]
          token_name = 'Refreshed '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
          token = {'name': token_name, 'type': 'access_token', 'app_id': app_id, 'access_token': new_access_token}
          if new_refresh_token:
            token['refresh_token'] = new_refresh_token
          self.context['access_tokens'][str(time.time())] = token
      
      self.end_result_table()
      
    except AduneoError as error:
      self.add_html("""<div class="intertable">Erreur lors de l'appel à refresh : {error}""".format(error=html.escape(str(error))))
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html("""<div class="intertable">Erreur lors de l'appel à refresh : {error}""".format(error=html.escape(str(error))))
    
    self.add_menu()
    
    self.send_page()

