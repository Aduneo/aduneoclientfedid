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
import base64
import copy
import hashlib
import html
import json
import jwcrypto.jwt
import jwcrypto.jwk
import random
import string
import time
import traceback
import urllib.parse
import uuid

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import RequesterForm
from ..Configuration import Configuration
from ..Context import Context
from ..Help import Help
from ..JWT import JWT
from ..WebRequest import WebRequest
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler

# TODO : implémentation RFC 8707 (paramètre resource, mais attention, il peut être multivalué - il faut faire évoluer CfiForm)


@register_web_module('/client/oauth2/login')
class OAuthClientLogin(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=True)
  def prepare_request(self):
    """
      Prépare la requête d'autorisation OAuth 2

    Versions:
      23/08/2024 (mpham) version initiale copiée d'OIDC
      28/11/2024 (mpham) on modifiait l'objet de configuration, de manière permanente s'il était enregistré par la suite
      28/11/2024 (mpham) on n'envoie pas les éléments vides du formulaire (Keycloak tombe en erreur sinon)
      04/12/2024 (mpham) new auth : on conserve le contexte, mais on récupère les paramètres de la configuration
      23/12/2024 (mpham) les valeurs des select sont maintenant toutes des constantes du type metadata_uri et non plus des libellés comme Authorization Server Metadata URI
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
      30/05/2025 (mpham) les méthodes d'authentification auprès de token étaient envore basic et form au client de client_secret_basic et lient_secret_post
      03/06/2025 (mpham) DNS override for OAuth 2 token, introspection, and revocaction endpoints
    """

    self.log_info('--- Start OAuth 2 flow ---')

    try:

      idp_id = self.get_query_string_param('idpid')
      app_id = self.get_query_string_param('appid')

      fetch_configuration_document = False

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
        oauth2_idp_params = idp_params.get('oauth2')
        if not oauth2_idp_params:
          raise AduneoError(f"OAuth2 IdP parameters have not been defined for IdP {idp_id}", button_label="IdP parameters", action=f"/client/idp/admin/modify?idpid={idp_id}")
        
        app_params = idp['oauth2_clients'][app_id]

        # On récupère name des paramètres de l'IdP
        idp_params['name'] = idp['name']

        # si le contexte existe, on le conserve (cas newauth)
        if self.context is None:
          self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'OAuth2'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

        if oauth2_idp_params.get('endpoint_configuration', 'local_configuration') == 'same_as_oidc':
          # récupération des paramètres OIDC pour les endpoints
          oidc_params = idp['idp_parameters'].get('oidc')
          if not oidc_params:
            raise AduneoError("can't retrieve endpoint parameters from OIDC configuration since OIDC is not configured")
          if oidc_params.get('endpoint_configuration') == 'same_as_oauth2':
            raise AduneoError("can't retrieve endpoint parameters from OIDC configuration since OIDC is configured with same_as_oauth2")
          for param in ['endpoint_configuration', 'discovery_uri', 'authorization_endpoint', 'token_endpoint']:
            oauth2_idp_params[param] = oidc_params.get(param, '')
          if oauth2_idp_params.get('endpoint_configuration') == 'discovery_uri':
            oauth2_idp_params['endpoint_configuration'] = 'metadata_uri'
            oauth2_idp_params['metadata_uri'] = oidc_params.get('discovery_uri')
        if oauth2_idp_params.get('endpoint_configuration', 'local_configuration') == 'metadata_uri':
          fetch_configuration_document = True

      else:
        # Rejeu de requête (conservée dans la session)
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        oauth2_idp_params = idp_params['oauth2']
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for client {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>IdP {idp_params['name']} OAuth2 Client {app_params['name']}</h1>")

      if fetch_configuration_document:
        self.add_html("""<div class="intertable">Fetching IdP configuration document from {url}</div>""".format(url=oauth2_idp_params['metadata_uri']))
        try:
          self.log_info('Starting metadata retrieval')
          self.log_info('metadata_uri: '+oauth2_idp_params['metadata_uri'])
          verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
          self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
          r = WebRequest.get(oauth2_idp_params['metadata_uri'], verify_certificate=verify_certificates)
          self.log_info(r.data)
          meta_data = r.json()
          oauth2_idp_params.update(meta_data)
          self.add_html("""<div class="intertable">Success</div>""")
        except Exception as error:
          self.log_error(traceback.format_exc())
          self.add_html(f"""<div class="intertable">Failed: {error}</div>""")
          return
        if r.status != 200:
          self.log_error('Server responded with code '+str(r.status))
          self.add_html(f"""<div class="intertable">Failed. Server responded with code {status}</div>""")
          return

      
      state = str(uuid.uuid4())

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(state, self.context['context_id'])

      oauth_flow = app_params.get('oauth_flow', 'authorization_code')
      if oauth_flow == 'authorization_code' or oauth_flow == 'authorization_code_pkce':
        flow_http_method = 'redirect'
        flow_url = oauth2_idp_params.get('authorization_endpoint', '')
      elif oauth_flow == 'resource_owner_password_credentials' or oauth_flow == 'client_credentials':
        flow_http_method = 'post'
        flow_url = oauth2_idp_params.get('token_endpoint', '')

      # Paramètres pour PKCE
      self.log_info(('  ' * 1)+'Code challenge generation in case Authorization code with PKCE flow is used')
      pkce_code_verifier = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(50))   # La RFC recommande de produire une suite de 32 octets encodés en base64url-encoded
      self.log_info(('  ' * 2)+'Code verifier: '+pkce_code_verifier)
      sha = hashlib.sha256()
      sha.update(pkce_code_verifier.encode('utf-8'))
      pkce_code_challenge = base64.urlsafe_b64encode(sha.digest()).decode('utf-8').replace('=', '')        
      self.log_info(('  ' * 2)+'Code challenge: '+pkce_code_challenge)

      form_content = {
        'contextid': self.context['context_id'],
        'redirect_uri': app_params.get('redirect_uri', ''),
        'authorization_endpoint': oauth2_idp_params.get('authorization_endpoint', ''),
        'token_endpoint': oauth2_idp_params.get('token_endpoint', ''),
        'introspection_endpoint': oauth2_idp_params.get('introspection_endpoint', ''),
        'introspection_http_method': oauth2_idp_params.get('introspection_http_method', 'post'),
        'introspection_auth_method': oauth2_idp_params.get('introspection_auth_method', 'basic'),
        'issuer': oauth2_idp_params.get('issuer', ''),
        'signature_key_configuration': oauth2_idp_params.get('signature_key_configuration', 'jwks_uri'),
        'jwks_uri': oauth2_idp_params.get('jwks_uri', ''),
        'signature_key': oauth2_idp_params.get('signature_key', ''),
        'token_endpoint_dns_override': oauth2_idp_params.get('token_endpoint_dns_override', ''),
        'introspection_endpoint_dns_override': oauth2_idp_params.get('introspection_endpoint_dns_override', ''),
        'revocation_endpoint_dns_override': oauth2_idp_params.get('revocation_endpoint_dns_override', ''),
        'oauth_flow': oauth_flow,
        'flow_url': flow_url,
        'flow_http_method': flow_http_method,
        'grant_type': 'client_credentials',
        'code_challenge_method': app_params.get('code_challenge_method', 'S256'),
        'code_challenge': pkce_code_challenge,
        'code_verifier': pkce_code_verifier,
        'client_id': app_params.get('client_id', ''),
        'scope': app_params.get('scope', ''),
        'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'basic'),
        'state': state,
      }
      
      form = RequesterForm('oauth2auth', form_content, action='/client/oauth2/login/sendrequest', mode='api', request_url='@[authorization_endpoint]') \
        .hidden('contextid') \
        .start_section('clientfedid_params', title="ClientFedID parameters") \
          .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri') \
        .end_section() \
        .start_section('as_endpoints', title="AS endpoints", collapsible=True, collapsible_default=False) \
          .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[oauth_flow] = 'authorization_code' or @[oauth_flow] = 'authorization_code_pkce'",
            on_change = """ 
              updateForFlow(cfiForm);
              """,
            ) \
          .text('token_endpoint', label='Token Endpoint', clipboard_category='token_endpoint',
            on_change = """ 
              updateForFlow(cfiForm);
              """,
            ) \
          .text('introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint') \
          .closed_list('introspection_http_method', label='Introspection request method', 
            values={'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
          .closed_list('introspection_auth_method', label='Introspection authn scheme', 
            values={'none': 'None', 'basic': 'Basic', 'bearer_token': 'Bearer Token'},
            default = 'basic'
            ) \
        .end_section() \
        .start_section('client_params', title="Client parameters", collapsible=True, collapsible_default=False) \
          .closed_list('oauth_flow', label='OAuth flow', 
            values={'authorization_code': 'Authorization Code', 'authorization_code_pkce': 'Authorization Code with PKCE', 'resource_owner_password_credentials': 'Resource Owner Password Credentials', 'client_credentials': 'Client Credentials'},
            default = 'authorization_code',
            on_change = """ 
              updateForFlow(cfiForm);
              """,
            ) \
          .hidden('flow_url') \
          .hidden('flow_http_method') \
          .text('grant_type', label='Grant type', displayed_when="@[oauth_flow] = 'client_credentials' or @[oauth_flow] = 'resource_owner_password_credentials'") \
          .closed_list('code_challenge_method', label='PKCE code challenge method', displayed_when="@[oauth_flow] = 'authorization_code_pkce'",
            values={'plain': 'plain', 'S256': 'S256'},
            default = 'S256'
            ) \
          .text('code_challenge', label='PKCE code challenge', displayed_when="@[oauth_flow] = 'authorization_code_pkce' and @[code_challenge_method] = 'S256'") \
          .text('code_verifier', label='PKCE code verifier', displayed_when="@[oauth_flow] = 'authorization_code_pkce'") \
          .text('client_id', label='Client ID', clipboard_category='client_id') \
          .password('client_secret', label='Client secret', clipboard_category='client_secret', displayed_when="@[token_endpoint_auth_method] = 'basic' or @[token_endpoint_auth_method] = 'form'") \
          .text('username', label='User name', clipboard_category='username', displayed_when="@[oauth_flow] = 'resource_owner_password_credentials'") \
          .password('password', label='User password', clipboard_category='userpassword', displayed_when="@[oauth_flow] = 'resource_owner_password_credentials'") \
          .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
          .closed_list('response_type', label='Reponse type', displayed_when="@[oauth_flow] = 'authorization_code' or @[oauth_flow] = 'authorization_code_pkce'",
            values={'code': 'code'},
            default = 'code'
            ) \
          .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
            values={'none': 'none', 'basic': 'client_secret_basic', 'form': 'client_secret_post'},
            default = 'basic'
            ) \
        .end_section() \
        .start_section('token_validation', title="Token validation (if JWT)", collapsible=True, collapsible_default=True) \
          .text('issuer', label='Issuer', clipboard_category='issuer') \
          .closed_list('signature_key_configuration', label='Signature key configuration',
            values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
            default = 'jwks_uri'
            ) \
          .text('jwks_uri', label='JWKS URI', displayed_when="@[signature_key_configuration] = 'jwks_uri'") \
          .text('signature_key', label='Signature key', displayed_when="@[signature_key_configuration] = 'local_configuration'") \
        .end_section() \
        .start_section('security_params', title="Security", collapsible=True, collapsible_default=False) \
          .text('state', label='State', displayed_when="@[oauth_flow] = 'authorization_code' or @[oauth_flow] = 'authorization_code_pkce'") \
        .end_section() \
        .start_section('clientfedid_configuration', title="ClientFedID Configuration", collapsible=True, collapsible_default=True) \
          .text('token_endpoint_dns_override', label='Token endpoint DNS override', clipboard_category='token_endpoint_dns_override') \
          .text('introspection_endpoint_dns_override', label='Introspection endpoint DNS override', clipboard_category='introspection_endpoint_dns_override') \
          .text('revocation_endpoint_dns_override', label='Revocation endpoint DNS override', clipboard_category='revocation_endpoint_dns_override') \
        .end_section() \

      form.set_request_parameters({
          'grant_type': '@[grant_type]',
          'client_id': '@[client_id]',
          'redirect_uri': '@[redirect_uri]',
          'scope': '@[scope]',
          'response_type': '@[response_type]',
          'state': '@[state]',
          'code_challenge_method': '@[code_challenge_method]',
          'code_challenge': '@[code_challenge]',
          'username': '@[username]',
          'password': '@[password]',
        }, 
        modifying_fields = ['oauth_flow', 'code_verifier'])
      form.modify_http_parameters({
        'request_url': '@[flow_url]',
        'form_method': '@[flow_http_method]',
        'body_format': 'x-www-form-urlencoded',
        'auth_method': '@[token_endpoint_auth_method]',
        'auth_login': '@[client_id]',
        'auth_secret': '@[client_secret]',
        'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
        })
      form.modify_visible_requester_fields({
        'request_url': True,
        'request_data': True,
        'body_format': False,
        'form_method': True,
        'auth_method': True,
        'verify_certificates': True,
        })
      form.set_data_generator_code("""
        return generateOAuth2Request(paramValues, cfiForm);;
      """)
      form.set_option('/requester/include_empty_items', False)

      self.add_html(form.get_html())
      self.add_javascript_include('/javascript/OAuthClientLogin.js')
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


  @register_page_url(url='sendrequest', method='POST', continuous=True)
  def send_request(self):
    
    """
    Récupère les informations saisies dans /oauth2/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oauth2/client/preparerequest
    
    Versions:
      23/08/2024 (mpham) version initiale copiée de OIDC
      27/02/2025 (mpham) les paramètres IdP n'étaient pas mis à jour au bon endroit
      28/02/2025 (mpham) code_verifier n'était pas conservé
      28/02/2025 (mpham) cinématiques Client credentials et Resource owner password credentials
      03/06/2025 (mpham) DNS override for OAuth 2 token, introspection and revocation endpoints
    """
    
    self.log_info('Redirection to IdP requested')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      for item in ['authorization_endpoint', 'token_endpoint', 'introspection_endpoint', 'introspection_http_method', 'introspection_auth_method', 'issuer', 'signature_key_configuration', 'jwks_uri', 'signature_key',
      'token_endpoint_dns_override', 'introspection_endpoint_dns_override', 'revocation_endpoint_dns_override']:
        oauth2_idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dans le contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['redirect_uri', 'oauth_flow', 'code_challenge_method', 'code_verifier', 'client_id', 'scope', 'token_endpoint_auth_method',
        'grant_type', 'username', 'password']:
        app_params[item] = self.post_form.get(item, '').strip()
        
      # Récupération du secret
      if self.post_form.get('client_secret', '') == '':
        # on va récupérer le secret dans la configuration
        conf_idp = self.conf['idps'][self.context.idp_id]
        conf_app = conf_idp['oauth2_clients'][self.context.app_id]
        app_params['client_secret'] = conf_app.get('client_secret!', '')
      else:
        app_params['client_secret'] = self.post_form.get('client_secret', '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'

      # Si on est en Resource Owner Password Credentials ou en Client Credentials, on fait une requête directe
      oauth_flow = self.post_form['oauth_flow']
      if oauth_flow == 'resource_owner_password_credentials':
        self._resource_owner_password_credentials()
      elif oauth_flow == 'client_credentials':
        self._client_credentials()
      else:

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
    """
      Callback provenant du navigateur (appel XHR dans le Javascript)
        La query string a pour origine l'AS ; elle ne fait que transiter par le Javascript du navigateur pour pouvoir ajouter facilement des requêtes dans la même page
        
      Regarde le flow correspondant au state retourné pour faire un simple routage vers
      - callback_flow_code_spa (Authorization Code et Authorization Code with PKCE)
    
    Versions:
      14/09/2022 (mpham) version initiale
      28/11/2024 (mpham) certificate verification is now a configuration parameter attached to the IDP and not the APP
      28/11/2024 (mpham) dans le contexte, on ajoute l'identifiant du client ayant récupéré les jetons
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
      30/05/2025 (mpham) les méthodes d'authentification auprès de token étaient envore basic et form au client de client_secret_basic et lient_secret_post
      03/06/2025 (mpham) DNS override for OAuth 2 token endpoint
    """
  
    self.add_javascript_include('/javascript/resultTable.js')
    self.add_javascript_include('/javascript/clipboard.js')
    try:

      self.log_info('Checking authorization')

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      if not idp_state:
        raise AduneoError(f"Can't retrieve request context from state because state in not present in callback query string {self.hreq.path}")
      self.log_info('for state: '+idp_state)

      context_id = self.get_session_value(idp_state)
      if not context_id:
        raise AduneoError(f"Can't retrieve request context from state because context id not found in session for state {idp_state}")

      self.context = self.get_session_value(context_id)
      if not self.context:
        raise AduneoError(f"Can't retrieve request context because context id {context_id} not found in session")
      
      # extraction des informations utiles de la session
      idp_id = self.context.idp_id
      app_id = self.context.app_id
      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      app_params = self.context.last_app_params

      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))

      self.add_html(f"<h3>OAuth 2 callback from {html.escape(idp_params['name'])} for client {html.escape(app_params['name'])}</h3>")

      self.start_result_table()
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')

      code = self.get_query_string_param('code')
      if not code:
        raise AduneoError("Authorization code not found in query string")

      token_endpoint = oauth2_idp_params.get('token_endpoint', '')
      if token_endpoint == '':
        raise AduneoError("Token endpoint missing from configuration")
      client_id = app_params['client_id']
      redirect_uri = app_params['redirect_uri']

      self.log_info('Start retrieving token for code '+code)
      self.log_info(('  ' * 1)+'from '+token_endpoint)
      self.add_result_row('Token endpoint', token_endpoint, 'token_endpoint')
      
      # Construction de la requête de récupération du jeton
      api_call_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'client_id': client_id,
      }
      if app_params['oauth_flow'] == 'authorization_code_pkce':
        api_call_data['code_verifier'] = app_params['code_verifier']

      token_endpoint_auth_method = app_params['token_endpoint_auth_method'].casefold()
      auth = None
      client_secret = None
      if app_params['oauth_flow'] == 'authorization_code':
      
        client_secret = app_params['client_secret']

        if token_endpoint_auth_method == 'basic':
          auth = (app_params['client_id'], client_secret)
        elif token_endpoint_auth_method == 'form':
          api_call_data['client_secret'] = client_secret
        else:
          raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be basic or form')

      self.log_info(('  ' * 1)+'Token request data: '+str(api_call_data))
      self.add_result_row('Token request data', json.dumps(api_call_data, indent=2), 'token_request_data')
      self.end_result_table()
      self.add_html('<div class="intertable">Fetching token...</div>')
      self.log_info("Start fetching token")
      try:
        self.log_info(('  ' * 1)+"sending request to "+token_endpoint)
        verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        
        token_endpoint_fqdn = urllib.parse.urlparse(token_endpoint).hostname
        dns_override = oauth2_idp_params.get('token_endpoint_dns_override', '')
        if dns_override != '':
          self.log_info(('  ' * 1)+f"DNS override: {token_endpoint_fqdn} is revolved to {dns_override}")
        else:
          dns_override = None
        
        r = WebRequest.post(token_endpoint, form=api_call_data, basic_auth=auth, verify_certificate=verify_certificates, dns_override=dns_override)

      except Exception as error:
        self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status == 200:
        self.add_html('<div class="intertable">Success</div>')
      else:
        self.add_html('<div class="intertable">Error, status code '+str(r.status)+'</div>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status)+", "+str(r.data)))
      
      response = r.json()
      self.log_info('AS response:')
      self.log_info(json.dumps(response, indent=2))
      self.start_result_table()
      self.add_result_row('Raw AS response', json.dumps(response, indent=2), 'as_raw_response')
      
      if 'access_token' not in response:
        raise AduneoError(self.log_error('access token not found in response'))

      # Affichage des jetons d'accès et de rafraîchissement
      access_token = response['access_token']
      refresh_token = response.get('refresh_token')
      self.display_tokens(access_token, refresh_token, idp_params, client_secret)
      
      # Nonce verification
      idp_nonce = response.get('nonce')
      if idp_nonce:
        session_nonce = request['nonce']
        if session_nonce == idp_nonce:
          self.log_info("Nonce verification OK: "+session_nonce)
          self.add_result_row('Nonce verification', 'OK: '+session_nonce, 'nonce_verification')
        else:
          self.log_error(('  ' * 1)+"Nonce verification failed")
          self.log_error(('  ' * 2)+"client nonce: "+session_nonce)
          self.log_error(('  ' * 2)+"IdP nonce   :"+idp_nonce)
          self.add_result_row('Nonce verification', "Failed\n  client nonce: "+session_nonce+"\n  IdP nonce: "+idp_nonce, 'nonce_verification')
          raise AduneoError('nonce verification failed')

      else:
        self.log_info('No nonce in response')

      self.end_result_table()

      # Enregistrement des jetons dans la session pour manipulation ultérieure
      #   Les jetons sont indexés par timestamp d'obtention
      token_name = 'Authz OAuth2 '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      token = {'name': token_name, 'type': 'access_token', 'app_id': app_id, 'access_token': access_token}
      if refresh_token:
        token['refresh_token'] = refresh_token
      self.context['access_tokens'][str(time.time())] = token

    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_html(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End OAuth 2 flow ---')

    self.add_menu() 

    self.send_page()


  def _client_credentials(self):
    """ Envoi de la requête Client Credentials à l'IdP
    
    Versions:
      28/05/2025 (mpham) version initiale
    """
    self.add_html("""<h2>Client credentials response</h2>""")

    try:

      self.log_info('Checking authorization with Client credentials flow')

      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      app_id = self.context.app_id
      app_params = self.context.last_app_params

      response = RequesterForm.send_form(self, self.post_form, default_secret=app_params['client_secret'])
      self.log_info('  Raw response: '+response.text)
      
      json_response = response.json()

      access_token = json_response['access_token']
      refresh_token = json_response.get('refresh_token')
      
      self.start_result_table()
      self.log_info('Token response'+json.dumps(json_response, indent=2))
      self.add_result_row('Token response', json.dumps(json_response, indent=2), 'token_response', expanded=True)
      self.display_tokens(access_token, refresh_token, idp_params, None)
      self.end_result_table()

      # Enregistrement des jetons dans la session pour manipulation ultérieure
      #   Les jetons sont indexés par timestamp d'obtention
      token_name = 'Authz OAuth2 '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      token = {'name': token_name, 'type': 'access_token', 'app_id': app_id, 'access_token': access_token}
      if refresh_token:
        token['refresh_token'] = refresh_token
      self.context['access_tokens'][str(time.time())] = token

    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_html(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End OAuth 2 flow ---')

    self.add_menu() 
    self.send_page()


  def _resource_owner_password_credentials(self):
    """ Envoi de la requête Resource owner password credentials à l'IdP
    
    Versions:
      28/05/2025 (mpham) version initiale
    """
    self.add_html("""<h2>Client Resource owner password credentials</h2>""")

    try:

      self.log_info('Checking authorization with Resource owner password credentials flow')

      idp_params = self.context.idp_params
      oauth2_idp_params = idp_params['oauth2']
      app_id = self.context.app_id
      app_params = self.context.last_app_params

      response = RequesterForm.send_form(self, self.post_form, default_secret=app_params['client_secret'])
      self.log_info('  Raw response: '+response.text)
      
      json_response = response.json()

      access_token = json_response['access_token']
      refresh_token = json_response.get('refresh_token')
      
      self.start_result_table()
      self.log_info('Token response'+json.dumps(json_response, indent=2))
      self.add_result_row('Token response', json.dumps(json_response, indent=2), 'token_response', expanded=True)
      self.display_tokens(access_token, refresh_token, idp_params, None)
      self.end_result_table()

      # Enregistrement des jetons dans la session pour manipulation ultérieure
      #   Les jetons sont indexés par timestamp d'obtention
      token_name = 'Authz OAuth2 '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      token = {'name': token_name, 'type': 'access_token', 'app_id': app_id, 'access_token': access_token}
      if refresh_token:
        token['refresh_token'] = refresh_token
      self.context['access_tokens'][str(time.time())] = token

    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_html(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End OAuth 2 flow ---')

    self.add_menu() 
    self.send_page()


  def display_tokens(self, access_token:str, refresh_token:str, idp_params:dict, client_secret:str):

      oauth2_idp_params = idp_params['oauth2']

      self.add_result_row('Access Token', access_token, 'access_token')
      if refresh_token:
        self.add_result_row('Refresh token', refresh_token, 'refresh_token')

      if JWT.is_jwt(access_token):
        # l'AT est un JWT, on l'affiche
        self.add_result_row('Access Token Type', 'JWT')
        jwt = JWT(access_token)
        self.add_result_row('Access Token Header', json.dumps(jwt.header, indent=2), 'access_token_header')
        self.log_info("Access token header:")
        self.log_info(json.dumps(jwt.header, indent=2))

        self.add_result_row('Access Token Payload', json.dumps(jwt.payload, indent=2), 'access_token_payload')
        self.log_info("Access token payload:")
        self.log_info(json.dumps(jwt.payload, indent=2))
        
        # On vérifie la signature du JWT
        alg = jwt.header.get('alg')
        if not alg:
          self.add_result_row('RT Signature Validation', 'JWT without algorithm in header')
          self.log_info("  Can't verify Refresh Token signature : JWT without algorithm in header")
        else:
          
          access_token_jwk = None
          if alg.startswith('HS'):
            self.log_info('HMAC signature, the secret is client_secret')
            encoded_secret = base64.urlsafe_b64encode(str.encode(client_secret)).decode()
            access_token_jwk = {"alg":alg,"kty":"oct","use":"sig","kid":"1","k":encoded_secret}
          else:
            # Signature asymétrique, on récupère la clé
            if oauth2_idp_params['signature_key_configuration'] == 'Local configuration':
            
              # Clé de signature donnée dans la configuration
              self.log_info('Signature JWK:')
              self.log_info(oauth2_idp_params['signature_key'])
              access_token_jwk = json.loads(oauth2_idp_params['signature_key'])

            else:
            
              # Clé à récupérer auprès de l'IdP
              self.log_info("Starting IdP keys retrieval")
              self.add_result_row('JWKS endpoint', oauth2_idp_params['jwks_uri'], 'jwks_endpoint')
              self.end_result_table()
              self.add_html('<div class="intertable">Fetching public keys...</div>')
              try:
                verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
                self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
                r = WebRequest.get(oauth2_idp_params['jwks_uri'], verify_certificate=verify_certificates)
              except Exception as error:
                self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
                raise AduneoError(self.log_error(('  ' * 2)+'IdP keys retrieval error: '+str(error)))
              if r.status == 200:
                self.add_html('<div class="intertable">Success</div>')
              else:
                self.add_html('<div class="intertable">Error, status code '+str(r.status)+'</div>')
                raise AduneoError(self.log_error('IdP keys retrieval error: status code '+str(r.status)))

              keyset = r.json()
              self.log_info("IdP response:")
              self.log_info(json.dumps(keyset, indent=2))
              self.start_result_table()
              self.add_result_row('Keyset', json.dumps(keyset, indent=2), 'keyset')
              
              # On en extrait les JWK qui correspondent aux jetons
              self.add_result_row('Retrieved keys', '', 'retrieved_keys', copy_button=False)
          
              for jwk in keyset['keys']:
                  self.add_result_row(jwk['kid'], json.dumps(jwk, indent=2))
                  if jwk['kid'] == jwt.header.get('kid'):
                    access_token_jwk = jwk

          if not access_token_jwk:
            self.add_result_row('AT Signature Validation', 'Signature key not found')
            self.log_info("  Can't verify AT signature : signature key not found")
          else:
            self.log_info('Signature JWK:')
            self.log_info(json.dumps(access_token_jwk, indent=2))
            self.add_result_row('Signature JWK', json.dumps(access_token_jwk, indent=2), 'signature_jwk')
            
            if jwt.is_signature_valid(access_token_jwk, raise_exception=False):
              self.log_info('Access Token signature verification OK')
              self.add_result_row('AT Signature verification', 'OK', copy_button=False)
            else:
              self.add_result_row('AT Signature verification', 'Failed', copy_button=False)
        
      else:
        self.add_result_row('Access Token Type', 'opaque')
      
      if refresh_token:
        if JWT.is_jwt(refresh_token):
          # le RT est un JWT, on l'affiche
          self.add_result_row('Refresh Token Type', 'JWT')
          jwt = JWT(refresh_token)
          self.add_result_row('Refresh Token Header', json.dumps(jwt.header, indent=2), 'refresh_token_header')
          self.log_info("Refresh token header:")
          self.log_info(json.dumps(jwt.header, indent=2))

          self.add_result_row('Refresh Token Payload', json.dumps(jwt.payload, indent=2), 'refresh_token_payload')
          self.log_info("Refresh token payload:")
          self.log_info(json.dumps(jwt.payload, indent=2))
          
          # Pas de vérification de signature du RT (aucun besoin, le RT est uniquement à renvoyer à l'IdP)
        else:
          self.add_result_row('Refresh Token Type', 'opaque')
