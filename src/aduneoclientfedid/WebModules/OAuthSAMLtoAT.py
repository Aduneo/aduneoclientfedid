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
from ..WebRequest import WebRequest
from ..Help import Help
from ..CfiForm import RequesterForm
from .FlowHandler import FlowHandler

"""
  Récupère un jeton d'accès en échange d'une assertion SAML (RFC 7522)

  Utilise les éléments du contexte
"""


@register_web_module('/client/oauth2/samltoat')
class OAuth2SAMLtoAT(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', continuous=True)
  def prepare_request(self):
    """ Prépare une requête d'échange de jeton

      La requête est transmise à sendrequest pour exécution
    
    Versions:
      26/02/2025 (mpham) version initiale adaptée de SAMLClientLogin.oauth_exchange_spa
    """
    
    try:

      self.log_info('SAML to Access Token flow: preparing the request')

      if not self.context:
        raise AduneoError("Can't retrieve request context from session")

      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      idp_params = self.conf['idps'][self.context.idp_id]
      self.log_info(('  ' * 1)+'IdP: '+idp_params['name'])

      # Récupération des token endpoints OIDC et OAuth 2
      self._fetch_token_endpoints(idp_params)

      # clients OIDC et OAuth 2
      app_ids = {'__input__': 'Direct Input'}
      client_table = {'__input__': {'name': 'Direct Input', 'client_id': '', 'token_endpoint': ''}}
      for app_id in idp_params.get('oidc_clients', {}):
        app_params = idp_params['oidc_clients'][app_id]
        app_ids[app_id] = app_params['name']
        client_table[app_id] = {'type': 'oidc', 'name': app_params['name'], 'client_id': app_params['client_id'], 'token_endpoint': self.oidc_token_endpoint}
      for app_id in idp_params.get('oauth2_clients', {}):
        app_params = idp_params['oauth2_clients'][app_id]
        app_ids[app_id] = app_params['name']
        client_table[app_id] = {'type': 'oauth2', 'name': app_params['name'], 'client_id': app_params['client_id'], 'token_endpoint': self.oauth2_token_endpoint}

      # assertions SAML
      default_assertion = '__input__'
      assertions = {'__input__': 'Direct Input'}
      for wrapper_key in sorted(self.context['saml_assertions'].keys(), reverse=True):
        wrapper = self.context['saml_assertions'][wrapper_key]
        assertions[wrapper['saml_assertion']] = wrapper['name']
        if default_assertion == '__input__':
          default_assertion = wrapper['saml_assertion']

      form_content = {
        'contextid': self.context['context_id'],
        'grant_type': 'urn:ietf:params:oauth:grant-type:saml2-bearer',
        'known_assertions': default_assertion,
        'assertion': default_assertion if default_assertion != '__input__' else '',
        'assertion_name': assertions[default_assertion] if default_assertion != '__input__' else '',
        'app_id': '__input__',
        'app_type': '',
        'token_endpoint': '',
        'client_id': '',
        'client_secret': '',
        'scope': '',
      }
      form = RequesterForm('samltoat', form_content, action='/client/oauth2/samltoat/sendrequest', request_url='@[token_endpoint]', mode='api') \
        .hidden('contextid') \
        .text('grant_type', label='Grant type', clipboard_category='grant_type') \
        .closed_list('known_assertions', label='Known SAML assertions', 
          values = assertions,
          default = default_assertion,
          on_change = """let knownAssertion = cfiForm.getThisFieldValue(); 
            if (knownAssertion != '__input__') {
              cfiForm.setFieldValue('assertion', knownAssertion);
              cfiForm.setFieldValue('assertion_name', cfiForm.getTable('client_table')[knownAssertion]);
            }
            """,
          ) \
        .hidden('assertion_name') \
        .text('assertion', label='SAML assertion', clipboard_category='saml_assertion', displayed_when="@[known_assertions] = '__input__'") \
        .closed_list('app_id', label='Client', 
          values = app_ids,
          default = '__input__',
          on_change = """let appId = cfiForm.getThisFieldValue(); 
            if (appId != '__input__') {
              cfiForm.setFieldValue('app_type', cfiForm.getTable('client_table')[appId]['type']);
              cfiForm.setFieldValue('token_endpoint', cfiForm.getTable('client_table')[appId]['token_endpoint']);
              cfiForm.setFieldValue('client_id', cfiForm.getTable('client_table')[appId]['client_id']);
            }
            """,
          ) \
        .hidden('app_type') \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[app_id] = '__input__'") \
        .text('client_id', label='Client ID', clipboard_category='client_id', displayed_when="@[app_id] = '__input__'") \
        .password('client_secret', label='Client secret', clipboard_category='client_secret', displayed_when="@[app_id] = '__input__'") \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('auth_method', label='Authn. Method', 
          values = {'none': 'None', 'basic': 'Basic', 'form': 'Form'},
          default = 'basic'
          ) \
        
      form.set_title('SAML Assertion to Access Token '+idp_params['name'])
      form.set_table('client_table', client_table)
      form.set_table('assertion_table', assertions)
      form.set_request_parameters({
        'grant_type': '@[grant_type]',
        'assertion': '@[assertion]',
        'scope': '@[scope]',
      })
      form.modify_http_parameters({
        'request_url': '@[token_endpoint]',
        'auth_method': '@[auth_method]',
        'auth_login': '@[client_id]',
        'auth_secret': '@[client_secret]',
        'verify_certificates': Configuration.is_on(idp_params['idp_parameters'].get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'form_method': True,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_data_generator_code("""
        // il faut coder l'assertion en Base64url
        xml_assertion = cfiForm.getFieldValue('assertion');
        paramValues['assertion'] = btoa(Array.from(Uint8Array.from(xml_assertion.split("").map(x => x.charCodeAt())), b => String.fromCharCode(b)).join(''))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
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
      26/02/2025 (mpham) version initiale adaptée de SAMLClientLogin.oauth_exchange_spa
    """
    
    #self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre>')

    try:

      if not self.context:
        raise AduneoError("Context not found in session")

      # récupération du secret
      client_secret = self.post_form.get('client_secret', '')
      if client_secret == '':
        # on va chercher le secret dans la configuration
        app_id = self.post_form.get('app_id')
        if app_id:
          conf_idp = self.conf['idps'][self.context.idp_id]
          if self.post_form.get('app_type') == 'oidc':
            conf_app = conf_idp['oidc_clients'][app_id]
            client_secret = conf_app.get('client_secret!', '')
          elif self.post_form.get('app_type') == 'oauth2':
            conf_app = conf_idp['oauth2_clients'][app_id]
            client_secret = conf_app.get('client_secret!', '')
    
      response = RequesterForm.send_form(self, self.post_form, default_secret=client_secret)
      json_response = response.json()
      
      self.start_result_table()
      self.log_info('Token exchange response'+json.dumps(json_response, indent=2))
      self.add_result_row('Token exchange response', json.dumps(json_response, indent=2), 'userinfo_response', expanded=True)
      self.end_result_table()
      
      if response.status_code == 200:

        token_name = 'Exchange from '+self.post_form.get('assertion_name', '?')+' - '+time.strftime("%H:%M:%S", time.localtime())
        
        if json_response.get('access_token'):
          token = {'name': token_name, 'app_id': self.post_form.get('app_id'), 'type': 'access_token', 'access_token': json_response['access_token']}
          self.context['access_tokens'][str(time.time())] = token
      
    except AduneoError as error:
      self.add_html("""<div class="intertable">Error during SAML to Access Token: {error}""".format(error=html.escape(str(error))))
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html("""<div class="intertable">Error during SAML to Access Token: {error}""".format(error=html.escape(str(error))))

    self.log_info('-- End SAML to Access Token flow')
    
    self.add_menu()
    
    self.send_page()


  def _fetch_token_endpoints(self, idp):
    """ Récupère les token endpoints OIDC et OAuth2 de l'IdP

    dans les membres
      - self.oidc_token_endpoint (None si n'existe pas)
      - self.oauth2_token_endpoint (None si n'existe pas)

    Args:
      idp : configuration de l'IdP

    Versions:
      26/02/2025 (mpham) version initiale
    """
    
    self.oidc_token_endpoint = None
    self.oauth2_token_endpoint = None
    
    idp_params = idp['idp_parameters']
    
    oidc_params = idp_params.get('oidc')
    oauth2_params = idp_params.get('oauth2')
    
    oidc_discovery_uri = None # on la conserve dans le cas (probable) où ce soit la même que celle d'OAuth 2
    if oidc_params:
      oidc_endpoint_configuration = oidc_params['endpoint_configuration']
      if oidc_endpoint_configuration == 'local_configuration':
        self.oidc_token_endpoint = oidc_params['token_endpoint']
      elif oidc_endpoint_configuration == 'discovery_uri':
        oidc_discovery_uri = oidc_params['discovery_uri']
        self.oidc_token_endpoint = self._fetch_token_endpoint_from_server(oidc_discovery_uri, Configuration.is_on(idp_params.get('verify_certificates', 'on')))
    if oauth2_params:
      oauth2_endpoint_configuration = oauth2_params['endpoint_configuration']
      if oauth2_endpoint_configuration == 'local_configuration':
        self.oidc_token_endpoint = oauth2_params['token_endpoint']
      elif oauth2_endpoint_configuration == 'metadata_uri':
        oauth2_discovery_uri = oauth2_params['metadata_uri']
        if oauth2_discovery_uri == oidc_discovery_uri:
          self.oauth2_token_endpoint = self.oidc_token_endpoint
        else:
          self.oauth2_token_endpoint = self._fetch_token_endpoint_from_server(oauth2_discovery_uri, Configuration.is_on(idp_params.get('verify_certificates', 'on')))
      elif oauth2_endpoint_configuration == 'same_as_oidc':
        self.oauth2_token_endpoint = self.oidc_token_endpoint
    if oidc_params:
      if oidc_endpoint_configuration == 'same_as_oauth2':
        self.oidc_token_endpoint = self.oauth2_token_endpoint
        
  
  def _fetch_token_endpoint_from_server(self, server_uri, verify_certificates:bool) -> str:
    """ Récupère un token endpoint OIDC ou OAuth2 depuis un document de configuration du serveur
      (discovery ou metadata)

    Args:
      server_uri : URL où récupérer le document de configuration

    Returns:
      URL de l'API de jeton, None s'il n'a pas été possible de la récupérer

    Versions:
      26/02/2025 (mpham) version initiale
    """
    
    token_endpoint = None
        
    self.add_html(f"""<div class="intertable">Fetching IdP configuration document from {server_uri}</div>""")
    
    try:
      self.log_info('Starting metadata retrieval')
      self.log_info('server_uri (discovery or metadata): '+server_uri)
      self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
      r = WebRequest.get(server_uri, verify_certificate=verify_certificates)
      self.log_info(r.data)
      if r.status == 200:
        meta_data = r.json()
        self.add_html("""<div class="intertable">Success</div>""")
        token_endpoint = meta_data.get('token_endpoint')
      else:
        self.log_error('Server responded with code '+str(r.status))
        self.add_html(f"""<div class="intertable">Failed. Server responded with code {status}</div>""")
    except Exception as error:
      self.log_error(traceback.format_exc())
      self.add_html(f"""<div class="intertable">Failed: {error}</div>""")

    return token_endpoint
        