"""
Copyright 2023 Aduneo

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
import datetime
import html
import json
import jwcrypto.jwt
import jwcrypto.jwk
import requests
import traceback
import uuid
import random
import string
import requests
import time
import urllib.parse

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import RequesterForm
from ..Configuration import Configuration
from ..Context import Context
from ..Help import Help
from ..JWT import JWT
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler

# TODO : implémentation RFC 8707 (paramètre resource, mais attention, il peut être multivalué - il faut faire évoluer CfiForm)


@register_web_module('/client/oauth2/login')
class OAuthClientLogin(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=False)
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
        idp_params = idp['idp_parameters'].get('oauth2')
        if not idp_params:
          raise AduneoError(f"OAuth2 IdP parameters have not been defined for IdP {idp_id}", button_label="IdP parameters", action=f"/client/idp/admin/modify?idpid={idp_id}")
        
        app_params = idp['oauth2_clients'][app_id]

        # On récupère name et verify_certificates des paramètres de l'IdP
        idp_params['name'] = idp['name']
        idp_params['verify_certificates'] = idp['idp_parameters']['verify_certificates']

        # si le contexte existe, on le conserve (cas newauth)
        if self.context is None:
          self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'OAuth2'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

        if idp_params.get('endpoint_configuration', 'local_configuration') == 'same_as_oidc':
          # récupération des paramètres OIDC pour les endpoints
          oidc_params = idp['idp_parameters'].get('oidc')
          if not oidc_params:
            raise AduneoError("can't retrieve endpoint parameters from OIDC configuration since OIDC is not configured")
          if oidc_params.get('endpoint_configuration') == 'same_as_oauth2':
            raise AduneoError("can't retrieve endpoint parameters from OIDC configuration since OIDC is configured with same_as_oauth2")
          for param in ['endpoint_configuration', 'discovery_uri', 'authorization_endpoint', 'token_endpoint']:
            idp_params[param] = oidc_params.get(param, '')
          if idp_params.get('endpoint_configuration') == 'discovery_uri':
            idp_params['endpoint_configuration'] = 'metadata_uri'
            idp_params['metadata_uri'] = oidc_params.get('discovery_uri')
        if idp_params.get('endpoint_configuration', 'local_configuration') == 'metadata_uri':
          fetch_configuration_document = True

      else:
        # Rejeu de requête (conservée dans la session)
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for client {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>IdP {idp_params['name']} OAuth2 Client {app_params['name']}</h1>")

      if fetch_configuration_document:
        self.add_html("""<div class="intertable">Fetching IdP configuration document from {url}</div>""".format(url=idp_params['metadata_uri']))
        try:
          self.log_info('Starting metadata retrieval')
          self.log_info('metadata_uri: '+idp_params['metadata_uri'])
          verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
          self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
          r = requests.get(idp_params['metadata_uri'], verify=verify_certificates)
          self.log_info(r.text)
          meta_data = r.json()
          idp_params.update(meta_data)
          self.add_html("""<div class="intertable">Success</div>""")
        except Exception as error:
          self.log_error(traceback.format_exc())
          self.add_html(f"""<div class="intertable">Failed: {error}</div>""")
          return
        if r.status_code != 200:
          self.log_error('Server responded with code '+str(r.status_code))
          self.add_html(f"""<div class="intertable">Failed. Server responded with code {status_code}</div>""")
          return

      
      state = str(uuid.uuid4())

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(state, self.context['context_id'])

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
        'authorization_endpoint': idp_params.get('authorization_endpoint', ''),
        'token_endpoint': idp_params.get('token_endpoint', ''),
        'introspection_endpoint': idp_params.get('introspection_endpoint', ''),
        'introspection_http_method': idp_params.get('introspection_http_method', 'post'),
        'introspection_auth_method': idp_params.get('introspection_auth_method', 'basic'),
        'issuer': idp_params.get('issuer', ''),
        'signature_key_configuration': idp_params.get('signature_key_configuration', 'jwks_uri'),
        'jwks_uri': idp_params.get('jwks_uri', ''),
        'signature_key': idp_params.get('signature_key', ''),
        'oauth_flow': app_params.get('oauth_flow', 'authorization_code'),
        'pkce_method': app_params.get('pkce_method', 'S256'),
        'pkce_code_verifier': pkce_code_verifier,
        'pkce_code_challenge': pkce_code_challenge,
        'client_id': app_params.get('client_id', ''),
        'scope': app_params.get('scope', ''),
        'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
        'state': state,
      }
      
      form = RequesterForm('oauth2auth', form_content, action='/client/oauth2/login/sendrequest', mode='new_page', request_url='@[authorization_endpoint]') \
        .hidden('contextid') \
        .start_section('clientfedid_params', title="ClientFedID parameters") \
          .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri') \
        .end_section() \
        .start_section('as_endpoints', title="AS endpoints", collapsible=True, collapsible_default=False) \
          .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint') \
          .text('token_endpoint', label='Token Endpoint', clipboard_category='token_endpoint') \
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
            values={'authorization_code': 'Authorization Code', 'authorization_code_pkce': 'Authorization Code with PKCE', 'resource_owner_password_predentials': 'Resource Owner Password Credentials', 'client_credentials': 'Client Credentials'},
            default = 'authorization_code'
            ) \
          .closed_list('pkce_method', label='PKCE code challenge method', displayed_when="@[oauth_flow] = 'authorization_code_pkce'",
            values={'plain': 'plain', 'S256': 'S256'},
            default = 'S256'
            ) \
          .text('pkce_code_verifier', label='PKCE code verifier', displayed_when="@[oauth_flow] = 'authorization_code_pkce'") \
          .text('pkce_code_challenge', label='PKCE code challenge', displayed_when="@[oauth_flow] = 'authorization_code_pkce' and @[pkce_method] = 'S256'") \
          .text('client_id', label='Client ID', clipboard_category='client_id') \
          .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
          .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
          .closed_list('response_type', label='Reponse type', 
            values={'code': 'code'},
            default = 'code'
            ) \
          .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
            values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
            default = 'client_secret_basic'
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
          .text('state', label='State') \
        .end_section() \

      form.set_request_parameters({
          'client_id': '@[client_id]',
          'redirect_uri': '@[redirect_uri]',
          'scope': '@[scope]',
          'response_type': '@[response_type]',
          'state': '@[state]',
          'pkce_method': '@[pkce_method]',
          'pkce_code_challenge': '@[pkce_code_challenge]',
        }, 
        modifying_fields = ['oauth_flow', 'pkce_code_verifier'])
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
        if (cfiForm.getField('oauth_flow').value == 'authorization_code_pkce') {
          if (cfiForm.getField('pkce_method').value == 'plain') {
            paramValues['pkce_code_challenge'] = cfiForm.getField('pkce_code_verifier').value;
          }
        } else {
          delete paramValues['pkce_method'];
          delete paramValues['pkce_code_challenge'];
        }
        return paramValues;
      """)
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
    Récupère les informations saisies dans /oauth2/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oauth2/client/preparerequest
    
    Versions:
      23/08/2024 (mpham) version initiale copiée de OIDC
    """
    
    self.log_info('Redirection to IdP requested')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      for item in ['authorization_endpoint', 'token_endpoint', 'introspection_endpoint', 'introspection_http_method', 'introspection_auth_method', 'issuer', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
        idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dans le contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['redirect_uri', 'oauth_flow', 'pkce_method', 'client_id', 'scope', 'token_endpoint_auth_method']:
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
      if oauth_flow == 'resource_owner_password_predentials':
        # TODO
        raise Exception("Resource Owner Password Credentials Flow not yet implemented")
      elif oauth_flow == 'client_credentials':
        # TODO
        raise Exception("Client Credentials Flow not yet implemented")
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

      token_endpoint = idp_params.get('token_endpoint', '')
      if not token_endpoint:
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
        api_call_data['code_verifier'] = app_params['pkce_code_verifier']

      token_endpoint_auth_method = app_params['token_endpoint_auth_method'].casefold()
      auth = None
      if app_params['oauth_flow'] == 'authorization_code':
      
        client_secret = app_params['client_secret']

        if token_endpoint_auth_method == 'client_secret_basic':
          auth = (app_params['client_id'], client_secret)
        elif token_endpoint_auth_method == 'client_secret_post':
          api_call_data['client_secret'] = client_secret
        else:
          raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be Basic or POST')

      self.log_info(('  ' * 1)+'Token request data: '+str(api_call_data))
      self.add_result_row('Token request data', json.dumps(api_call_data, indent=2), 'token_request_data')
      self.end_result_table()
      self.add_html('<div class="intertable">Fetching token...</div>')
      self.log_info("Start fetching token")
      try:
        self.log_info(('  ' * 1)+"sending request to "+token_endpoint)
        verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        r = requests.post(token_endpoint, api_call_data, auth=auth, verify=verify_certificates)
      except Exception as error:
        self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_html('<div class="intertable">Success</div>')
      else:
        self.add_html('<div class="intertable">Error, status code '+str(r.status_code)+'</div>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status_code)+", "+r.text))
      
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


  def display_tokens(self, access_token:str, refresh_token:str, idp_params:dict, client_secret:str):

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
            if idp_params['signature_key_configuration'] == 'Local configuration':
            
              # Clé de signature donnée dans la configuration
              self.log_info('Signature JWK:')
              self.log_info(idp_params['signature_key'])
              access_token_jwk = json.loads(idp_params['signature_key'])

            else:
            
              # Clé à récupérer auprès de l'IdP
              self.log_info("Starting IdP keys retrieval")
              self.add_result_row('JWKS endpoint', idp_params['jwks_uri'], 'jwks_endpoint')
              self.end_result_table()
              self.add_html('<div class="intertable">Fetching public keys...</div>')
              try:
                verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
                self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
                r = requests.get(idp_params['jwks_uri'], verify=verify_certificates)
              except Exception as error:
                self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
                raise AduneoError(self.log_error(('  ' * 2)+'IdP keys retrieval error: '+str(error)))
              if r.status_code == 200:
                self.add_html('<div class="intertable">Success</div>')
              else:
                self.add_html('<div class="intertable">Error, status code '+str(r.status_code)+'</div>')
                raise AduneoError(self.log_error('IdP keys retrieval error: status code '+str(r.status_code)))

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









  @register_page_url(url='callback_temp', method='GET', template='page_default.html', continuous=True)
  def callback_temp(self):
    """ Retour d'authentification depuis l'IdP
    
      Versions:
        23/08/2024 (mpham) version ini
    """

    self.add_javascript_include('/javascript/resultTable.js')
    self.add_javascript_include('/javascript/clipboard.js')
    self.start_result_table()
    try:
    
      self.log_info('Autorization callback')
      
      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      if not idp_state:
        raise AduneoError(f"Can't retrieve request context from state because state in not present in callback query string {self.hreq.path}")
      self.log_info('for state: '+idp_state)
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')

      context_id = self.get_session_value(idp_state)
      if not context_id:
        raise AduneoError(f"Can't retrieve request context from state because context id not found in session for state {idp_state}")

      self.context = self.get_session_value(context_id)
      if not self.context:
        raise AduneoError(f"Can't retrieve request context because context id {context_id} not found in session")
      
      # extraction des informations utiles de la session
      idp_id = self.context['current_flow']['idp_id']
      app_id = self.context['current_flow']['app_id']
      idp_params = self.context['current_flow']['idp_params']
      app_params = self.context['current_flow']['app_params']
      token_endpoint = idp_params['token_endpoint']
      client_id = app_params['client_id']
      redirect_uri = app_params['redirect_uri']
      
      if 'client_secret' in app_params:
        client_secret = app_params['client_secret']
      else:
        # il faut aller chercher le mot de passe dans la configuration
        conf_idp = self.conf['idps'][idp_id]
        conf_app = conf_idp['oauth2_clients'][app_id]
        client_secret = conf_app['client_secret!']

      token_endpoint_auth_method = app_params['token_endpoint_auth_method'].casefold()

      # Vérification de state (plus besoin puisqu'on utilise le state pour récupérer les informations dans la session)
      #session_state = request['state']
      #idp_state = url_params['state'][0]
      #if session_state != idp_state:
      #   print('ERROR')

      grant_type = "authorization_code";
      code = self.get_query_string_param('code')
      self.add_result_row('Code returned by IdP', code, 'idp_code')
      
      data = {
        'grant_type':grant_type,
        'code':code,
        'redirect_uri':redirect_uri,
        'client_id':client_id
        }
      
      auth = None
      if token_endpoint_auth_method == 'client_secret_basic':
        auth = (client_id, client_secret)
      elif token_endpoint_auth_method == 'client_secret_post':
        data['client_secret'] = client_secret
      else:
        raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be client_secret_basic or client_secret_post')
      
      self.add_result_row('Token endpoint', token_endpoint, 'token_endpoint')
      self.end_result_table()
      self.add_html('<div class="intertable">Fetching token...</div>')
      self.log_info("Start fetching token")
      try:
        self.log_info("Connecting to "+token_endpoint)
        verify_certificates = Configuration.is_on(app_params.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        # Remarque : ici on est en authentification client_secret_post alors que la méthode par défaut, c'est client_secret_basic (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
        r = requests.post(token_endpoint, data=data, auth=auth, verify=verify_certificates)
      except Exception as error:
        self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_html('<div class="intertable">Success</div>')
      else:
        self.add_html('<div class="intertable">Error, status code '+str(r.status_code)+'</div>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status_code)+", "+r.text))

      response = r.json()
      self.log_info("IdP response:")
      self.log_info(json.dumps(response, indent=2))
      id_token = response['id_token']
      self.start_result_table()
      self.add_result_row('JWT ID Token', id_token, 'jwt_id_token')
      
      self.log_info("Decoding ID token")
      token_items = id_token.split('.')
      encoded_token_header = token_items[0]
      token_header_string = base64.urlsafe_b64decode(encoded_token_header + '=' * (4 - len(encoded_token_header) % 4))
      encoded_token_payload = token_items[1]
      token_payload = base64.urlsafe_b64decode(encoded_token_payload + '=' * (4 - len(encoded_token_payload) % 4))

      token_header = json.loads(token_header_string)
      self.add_result_row('ID Token header', json.dumps(token_header, indent=2), 'id_token_header')
      self.log_info("ID token header:")
      self.log_info(json.dumps(token_header, indent=2))

      json_token = json.loads(token_payload)
      self.add_result_row('ID Token claims set', json.dumps(json_token, indent=2), 'id_token_claims_set')
      self.add_result_row('ID Token sub', json_token['sub'], 'id_token_sub')
      self.log_info("ID token payload:")
      self.log_info(json.dumps(json_token, indent=2))

      # Vérification de nonce
      session_nonce = self.context['current_flow']['nonce']
      idp_nonce = json_token['nonce']
      if session_nonce == idp_nonce:
        self.log_info("Nonce verification OK: "+session_nonce)
        self.add_result_row('Nonce verification', 'OK: '+session_nonce, 'nonce_verification')
      else:
        self.log_error(('  ' * 1)+"Nonce verification failed")
        self.log_error(('  ' * 2)+"client nonce: "+session_nonce)
        self.log_error(('  ' * 2)+"IdP nonce   :"+idp_nonce)
        self.add_result_row('Nonce verification', "Failed\n  client nonce: "+session_nonce+"\n  IdP nonce: "+idp_nonce, 'nonce_verification')
        raise AduneoError('nonce verification failed')

      # Vérification de validité du jeton
      self.log_info("Starting token validation")
      
      # On vérifie que le jeton est toujours valide (la date est au format Unix)
      tokenExpiryTimestamp = json_token['exp']
      tokenExpiryTime = datetime.datetime.utcfromtimestamp(tokenExpiryTimestamp)
      if tokenExpiryTime >= datetime.datetime.utcnow():
        self.log_info("Token expiration verification OK:")
        self.log_info("Token expiration: "+str(tokenExpiryTime)+' UTC')
        self.log_info("Now             : "+str(datetime.datetime.utcnow())+' UTC')
        self.add_result_row('Expiration verification', 'OK:'+str(tokenExpiryTime)+' UTC (now is '+str(datetime.datetime.utcnow())+' UTC)', 'expiration_verification')
      else:
        self.log_error(('  ' * 1)+"Token expiration verification failed:")
        self.log_error(('  ' * 2)+"Token expiration: "+str(tokenExpiryTime)+' UTC')
        self.log_error(('  ' * 2)+"Now             : "+str(datetime.datetime.utcnow())+' UTC')
        self.add_result_row('Expiration verification', 'Failed:'+str(tokenExpiryTime)+' UTC (now is '+str(datetime.datetime.utcnow())+' UTC)', 'expiration_verification')
        raise AduneoError('token expiration verification failed')
      
      # On vérifie l'origine du jeton 
      token_issuer = json_token['iss']
      if 'issuer' not in idp_params:
        raise AduneoError("Issuer missing in authentication configuration", explanation_code='oidc_missing_issuer')
      if token_issuer == idp_params['issuer']:
        self.log_info("Token issuer verification OK: "+token_issuer)
        self.add_result_row('Issuer verification', 'OK: '+token_issuer, 'issuer_verification')
      else:
        self.log_error(('  ' * 1)+"Expiration verification failed:")
        self.log_error(('  ' * 2)+"Token issuer   : "+token_issuer)
        self.log_error(('  ' * 2)+"Metadata issuer: "+idp_params['issuer'])
        self.add_result_row('Issuer verification', "Failed\n  token issuer: "+token_issuer+"\n  metadata issuer:"+meta_data['issuer'], 'issuer_verification')
        raise AduneoError('token issuer verification failed')
      
      # On vérifie l'audience du jeton, qui doit être le client ID
      token_audience = json_token['aud']
      comp_token_audience = token_audience
      if isinstance(comp_token_audience, str):
        # les spécifications indiquent que l'audience est un tableau en général, mais autorisent les chaînes simples
        comp_token_audience = [comp_token_audience]
      
      if client_id in token_audience:
        self.log_info("Token audience verification OK: "+str(token_audience))
        self.add_result_row('Audience verification', 'OK: '+str(token_audience), 'audience_verification')
      else:
        self.log_error(('  ' * 1)+"Audience verification failed:")
        self.log_error(('  ' * 2)+"Token audience: "+str(token_audience))
        self.log_error(('  ' * 2)+"ClientID      : "+client_id)
        self.add_result_row('Audience verification', 'Failed ('+client_id+' != '+str(token_audience), 'audience_verification')
        raise AduneoError('token audience verification failed')
      
      # Vérification de signature, on commence par regarde l'algorithme
      token_key = None
      keyset = None
      alg = token_header.get('alg')
      self.log_info('Signature verification')
      self.log_info('Signature algorithm in token header : '+alg)
      if alg is None:
        raise AduneoError('Signature algorithm not found in header '+json.dumps(token_header))
      elif alg.startswith('HS'):
        # Signature symétrique HMAC
        self.log_info('HMAC signature, the secret is client_secret')
        encoded_secret = base64.urlsafe_b64encode(str.encode(client_secret)).decode()
        key = {"alg":alg,"kty":"oct","use":"sig","kid":"1","k":encoded_secret}
        token_key = key

      else:
        # Signature asymétrique
        self.log_info('Asymmetric signature, fetching public key')
      
        # On regarde si on doit aller chercher les clés avec l'endpoint JWKS ou si la clé a été donnée localement
        if idp_params['signature_key_configuration'] == 'Local configuration':
          self.log_info('Signature JWK:')
          self.log_info(idp_params['signature_key'])
          token_jwk = json.loads(idp_params['signature_key'])
        else:
        
          # On extrait l'identifiant de la clé depuis l'id token
          idp_kid = token_header['kid']
          self.log_info('Signature key kid: '+idp_kid)
          self.add_result_row('Signature key kid', idp_kid, 'signature_key_kid')
          
          # on va chercher la liste des clés
          self.log_info("Starting IdP keys retrieval")
          self.add_result_row('JWKS endpoint', idp_params['jwks_uri'], 'jwks_endpoint')
          self.end_result_table()
          self.add_html('<div class="intertable">Fetching public keys...</div>')
          try:
            verify_certificates = Configuration.is_on(app_params.get('verify_certificates', 'on'))
            self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
            r = requests.get(idp_params['jwks_uri'], verify=verify_certificates)
          except Exception as error:
            self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
            raise AduneoError(self.log_error(('  ' * 2)+'IdP keys retrieval error: '+str(error)))
          if r.status_code == 200:
            self.add_html('<div class="intertable">Success</div>')
          else:
            self.add_html('<div class="intertable">Error, status code '+str(r.status_code)+'</div>')
            raise AduneoError(self.log_error('IdP keys retrieval error: status code '+str(r.status_code)))

          keyset = r.json()
          self.log_info("IdP response:")
          self.log_info(json.dumps(keyset, indent=2))
          self.start_result_table()
          self.add_result_row('Keyset', json.dumps(keyset, indent=2), 'keyset')
          
          # On en extrait la JWK qui correspond au token
          self.add_result_row('Retrieved keys', '', 'retrieved_keys', copy_button=False)
          token_jwk = None
          for jwk in keyset['keys']:
              self.add_result_row(jwk['kid'], json.dumps(jwk, indent=2))
              if jwk['kid'] == idp_kid:
                token_jwk = jwk
                
          self.log_info('Signature JWK:')
          self.log_info(json.dumps(token_jwk, indent=2))
          
        self.add_result_row('Signature JWK', json.dumps(token_jwk, indent=2), 'signature_jwk')
        token_key = token_jwk

      try:
        jwt = JWT(id_token)
        jwt.is_signature_valid(token_key)
        self.log_info('Signature verification OK')
        self.add_result_row('Signature verification', 'OK', copy_button=False)
      except Exception as error:
      
        default_case = True
        # Si on est en HS256, peut-être que le serveur a utilisé une clé autre que celle du client_secret (cas Keycloak)
        if alg == 'HS256':
          if idp_params['signature_key_configuration'] != 'Local configuration':
            self.log_info('HS256 signature, client_secret not working. The server might have used another key. Put this key in configuration')
          else:
            default_case = False
            self.log_info('HS256 signature, client_secret not working, trying key from configuration')
            
            configuration_key = idp_params['signature_key']
            self.log_info('Configuration key:')
            self.log_info(configuration_key)
            json_key = json.loads(configuration_key)
          
            token_key = json_key
          
            try:
              jwt.is_signature_valid(token_key)
              self.log_info('Signature verification OK')
              self.add_result_row('Signature verification', 'OK', copy_button=False)
            except Exception as error:
              default_case = True
          
        if default_case:
          # Cas normal de la signature non vérifiée
          self.add_result_row('Signature verification', 'Failed', copy_button=False)
          raise AduneoError(self.log_error('Signature verification failed'))

      op_access_token = response.get('access_token')
      if op_access_token:
        # Jeton d'accès pour authentification auprès de l'OP (userinfo en particulier)
        self.add_result_row('OP access token', op_access_token, 'op_access_token')
        self.log_info('OP access token: '+op_access_token)

      self.end_result_table()
      self.add_html('<h3>Authentication successful</h3>')
      
      # Enregistrement des jetons dans la session pour manipulation ultérieure
      #   Les jetons sont indexés par timestamp d'obtention
      token_name = 'Authn OIDC '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      token = {'name': token_name, 'type': 'id_token', 'id_token': id_token}
      if op_access_token:
        token['access_token'] = op_access_token
      self.context['id_tokens'][str(time.time())] = token

      # on considère qu'on est bien loggé
      self.logon('oauth_client_'+idp_id+'/'+app_id, id_token)

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

    self.log_info('--- End OpenID Connect flow ---')

    self.add_menu() 

    self.send_page()

































 
  @register_url(url='preparerequest_old', method='GET')
  def prepare_request_old(self):

    self.log_info('--- Start OAuth 2 flow ---')

    rp_id = self.get_query_string_param('id')
    context_id = self.get_query_string_param('contextid')

    context = None
    if context_id:
      context = self.get_session_value(context_id)

    if context is None:
      if rp_id is None:
        self.send_redirection('/')
        return
      else:
        # Nouvelle requête
        rp = self.conf['oauth_clients'][rp_id]
        self.log_info(('  ' * 1)+'for AS '+rp['name'])

        if rp.get('endpoint_configuration', 'Local configuration').casefold() == 'discovery uri':
          self.add_content('<span id="meta_data_ph">Retrieving metadata from<br>'+rp['discovery_uri']+'<br>...</span>')
          try:
            self.log_info('Starting metadata retrieval')
            self.log_info('discovery_uri: '+rp['discovery_uri'])
            verify_certificates = Configuration.is_on(rp.get('verify_certificates', 'on'))
            self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
            r = requests.get(rp['discovery_uri'], verify=verify_certificates)
            self.log_info(r.text)
            meta_data = r.json()
            self.add_content('<script>document.getElementById("meta_data_ph").style.display = "none"</script>')
            meta_data['signature_key'] = rp.get('signature_key', '')
          except Exception as error:
            self.log_error(traceback.format_exc())
            self.add_content('failed<br>'+str(error))
            self.send_page()
            return
          if r.status_code != 200:
            self.log_error('Server responded with code '+str(r.status_code))
            self.add_content('failed<br>Server responded with code '+str(r.status_code))
            self.send_page()
            return
        else:
          meta_data = {}
          meta_data = dict((k, rp[k]) for k in ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri', 'introspection_endpoint', 'signature_key'] if k in rp)

    else:
      # Rejeu de requête (conservée dans la session)
      rp_id = context['initial_flow']['app_id']
      rp = context['request']
      #self.del_session_value(state)   TODO
      
      conf_rp = self.conf['oauth_clients'][rp_id]
      rp['name'] = conf_rp['name']
      meta_data = context['meta_data']
      self.log_info(('  ' * 1)+'for AS '+rp['name'])

    name = rp.get('name')
    discovery_uri = rp.get('discovery_uri'),
    authorization_endpoint = meta_data['authorization_endpoint']
    token_endpoint = meta_data['token_endpoint']
    introspection_endpoint = meta_data['introspection_endpoint']
    client_id = rp.get('client_id')
    token_endpoint_auth_method = rp.get('token_endpoint_auth_method', 'POST')
    redirect_uri = rp.get('redirect_uri')
    discovery_uri = rp.get('discovery_uri')
    scope = rp.get('scope', '')
    resource = rp.get('resource', '')
    response_type = 'code'
    response_mode = 'query'
    state = uuid.uuid4()
    nonce = uuid.uuid4()
    rs_client_id = rp.get('rs_client_id', '')
    verify_certificates = Configuration.is_on(rp.get('verify_certificates', 'on'))

    # Paramètres pour PKCE
    self.log_info(('  ' * 1)+'Code challenge generation in case Authorization code with PKCE flow is used')
    pkce_code_verifier = ''.join(random.choice(string.ascii_letters+string.digits) for i in range(50))   # La RFC recommande de produire une suite de 32 octets encodés en base64url-encoded
    self.log_info(('  ' * 2)+'Code verifier: '+pkce_code_verifier)
    sha = hashlib.sha256()
    sha.update(pkce_code_verifier.encode('utf-8'))
    pkce_code_challenge = base64.urlsafe_b64encode(sha.digest()).decode('utf-8').replace('=', '')        
    self.log_info(('  ' * 2)+'Code challenge: '+pkce_code_challenge)

    self.send_template(
      'OAuthPrepareRequest.html',
      rp_id = rp_id,
      name=name,
      authorization_endpoint = authorization_endpoint,
      pkce_code_verifier = pkce_code_verifier,
      pkce_code_challenge = pkce_code_challenge,
      token_endpoint = token_endpoint,
      signature_key_configuration = 'JWKS URI',
      jwks_uri = 'https:// à chercher dans les méta data',  # TODO
      signature_key = 'signature_key',
      client_id=client_id,
      token_endpoint_auth_method=token_endpoint_auth_method,
      redirect_uri=redirect_uri,
      scope=scope,
      resource=resource,
      response_type=response_type,
      response_mode=response_mode,
      introspection_endpoint = introspection_endpoint,
      rs_client_id = rs_client_id,
      state=state,
      nonce=nonce,
      verify_certificates = ' checked' if verify_certificates else '',
      remember_secrets = Configuration.is_parameter_on(self.conf, '/preferences/clipboard/remember_secrets', False),
      )


  @register_url(url='sendrequest_old', method='POST')
  def send_request_old(self):
    """
    Récupère les informations saisies dans /client/oauth/login/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /client/oauth/login/preparerequest et placée dans le paramètre authentication_request
    
    Versions:
      00/00/2022 (mpham) : version initiale
      23/12/2022 (mpham) : ajout de token_endpoint_auth_method
    """

    self.log_info('Redirection to IdP requested')
    state = self.post_form['state']

    rp_id = self.post_form['rp_id']
    context = {"context_id": state, "initial_flow": {"app_id": rp_id, "flow_type": "OAuth2"}, "request": {}, "tokens": {}}
    
    meta_data = {}
    for item in ['authorization_endpoint', 'token_endpoint', 'introspection_endpoint', 'jwks_uri', 'signature_key']:
      if self.post_form[item] != '':
        meta_data[item] = self.post_form[item]
    
    context['meta_data'] = meta_data
    
    request = {}
    context['request'] = request
    for item in ['flow', 'rp_id', 'scope', 'response_type', 'client_id', 'client_secret!', 'token_endpoint_auth_method', 
      'redirect_uri', 'state', 'nonce', 'pkce_code_challenge_method', 'pkce_code_verifier', 'pkce_code_challenge', 'signature_key_configuration', 
      'validation_method', 'rs_client_id', 'rs_client_secret!', 'resource'
      ]:
      if self.post_form[item] != '':
        request[item] = self.post_form[item]

    for item in ['verify_certificates']:
      if item in self.post_form:
        request[item] = 'on'
      else:
        request[item] = 'off'
    
    self.set_session_value(state, context)
    
    authentication_request = self.post_form['authentication_request']
    self.log_info('Redirecting to:')
    self.log_info(authentication_request)
    self.send_redirection(authentication_request)


  @register_url(method='GET')
  def callback_old(self):
    """
      Retour de redirection de l'Authorization Server (AS), après l'authentification initiale de l'utilisateur
      
      Initialise la page d'échange en Javascript qui va accueillir les échanges ultérieures (rafraichissement, token exchange)
        Cette page fait un appel aux API du client de fédération par XHR et ajoute le HTML retourné dans la page
        
        Ca permet de rester sur la même page tout en faisant des interactions avec l'AS
      
      mpham 13/09/2022
    """

    self.log_info('Callback from Authorization Server. Query string: '+self.hreq.path)
    self.log_info('Query string: '+self.hreq.path)

    self.add_content(Help.help_window_definition())
    self.add_content(Clipboard.get_window_definition())
    self.add_content("""
    <script src="/javascript/resultTable.js"></script>
    <script src="/javascript/requestSender.js"></script>
    <div id="text_ph"></div>
    <div id="end_ph"></div>
    
    <script>
    getHtml("GET", "/client/oauth/login/callback_spa"+window.location.search, 'GET')
    </script>
    
    """)
    self.send_page()
  
  
  @register_url(method='GET')
  def callback_spa(self):
    """
      Callback provenant du navigateur (appel XHR dans le Javascript)
        La query string a pour origine l'AS ; elle ne fait que transiter par le Javascript du navigateur pour pouvoir ajouter facilement des requêtes dans la même page
        
      Regarde le flow correspondant au state retourné pour faire un simple routage vers
      - callback_flow_code_spa (Authorization Code et Authorization Code with PKCE)
      
    mpham 14/09/2022
    """
  
    try:

      self.log_info('Checking authorization')

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      self.log_info('for state: '+idp_state)
      
      context = self.get_session_value(idp_state)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))
      
      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))

      rp = self.conf['oauth_clients'][request['rp_id']]
      self.add_content("<h3>OAuth 2 callback for "+html.escape(rp['name'])+"</h3>")

      # si le secret n'a ps été saisi dans le formulaire, on va le chercher dans la configuration
      if 'client_secret!' not in request:
        request['client_secret!'] = rp.get('client_secret!')

      # routage en fonction de la cinématique
      flow = request.get('flow')
      if flow == 'Authorization Code' or flow == 'Authorization Code with PKCE':
        self.callback_flow_code_spa(context)
      else:
        raise AduneoError(self.log_error('Unknown flow '+flow))
      
    except AduneoError as error:
      self.add_content('<h3>Authentication failed : '+html.escape(str(error))+'</h3>')
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Authentication failed : '+html.escape(str(error))+'</h3>')
    
    self.send_page_raw()
    

  def callback_flow_code_spa(self, context:dict):
    """
      Callback de flow Authorization Code ou Authorization Code with PKCE
      
    Versions:
    14/09/2022 (mpham) : version initiale
    23/12/2022 (mpham) : possibilité de choisir la méthode d'authentification par token_endpoint_auth_method
    """
  
    request = context['request']
  
    access_token = None
    self.start_result_table()
    self.add_result_row('State returned by IdP', request['state'], 'idp_state')
    try:

      self.log_info('OAuth 2 callback for flow '+request['flow'])
      self.add_result_row('Flow', request['flow'], 'flow')

      code = self.get_query_string_param('code')
      self.log_info('Start retrieving token for code '+code)
      
      token_endpoint = context['meta_data']['token_endpoint']
      self.log_info(('  ' * 1)+'from '+token_endpoint)
      
      # Construction de la requête de récupération du jeton
      api_call_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': request['redirect_uri'],
        'client_id': request['client_id'],
      }
      resource = request.get('resource','')
      if resource != '':
        api_call_data['resource'] = resource
      if request['flow'] == 'Authorization Code with PKCE':
        api_call_data['code_verifier'] = request['pkce_code_verifier']

      token_endpoint_auth_method = request['token_endpoint_auth_method'].casefold()
      auth = None
      if request['flow'] == 'Authorization Code':
        if token_endpoint_auth_method == 'basic':
          auth = (request['client_id'], request['client_secret!'])
        elif token_endpoint_auth_method == 'post':
          api_call_data['client_secret'] = request['client_secret!']
        else:
          raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be Basic or POST')

      self.log_info(('  ' * 1)+'Token request data: '+str(api_call_data))
      self.add_result_row('Token request data', json.dumps(api_call_data, indent=2), 'token_request_data')
      
      url = token_endpoint+'?'+urllib.parse.urlencode(api_call_data)
      self.log_info(('  ' * 1)+'URL: '+url)
      self.add_result_row('Token request URL', url, 'token_request_url')
      
      self.add_content('<tr><td>Retrieving tokens...</td>')
      try:
        self.log_info(('  ' * 1)+"sending request to "+token_endpoint)
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        r = requests.post(token_endpoint, api_call_data, auth=auth, verify=verify_certificates)
      except Exception as error:
        self.add_content('<td>Error : '+str(error)+'</td><td></td></tr>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_content('<td>OK</td><td></td></tr>')
      else:
        self.add_content('<td>Error, status code '+str(r.status_code)+': '+html.escape(r.text)+'</td></tr>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status_code)+", "+r.text))
      
      response = r.json()
      self.log_info('AS response:')
      self.log_info(json.dumps(response, indent=2))
      self.add_result_row('Raw AS response', json.dumps(response, indent=2), 'as_raw_response')
      
      if 'access_token' not in response:
        raise AduneoError(self.log_error('access token not found in response'))
      
      access_token = response['access_token']
      self.add_result_row('Access token', access_token, 'access_token')
      refresh_token = response.get('refresh_token')
      if refresh_token:
        self.add_result_row('Refresh token', refresh_token, 'refresh_token')
      
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
      self.validate_access_token(request, access_token)
      context['tokens'] = {'access_token': access_token}
      if refresh_token:
        context['tokens']['refresh_token'] = refresh_token
      self.set_session_value(request['state'], context)
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h4>Callback error: '+html.escape(str(error))+'</h4>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Callback error: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End OAuth 2 flow ---')

    self._add_footer_menu(context) 

      
      
  def validate_access_token(self, request:dict, access_token:str):
    """ Lance la validation d'un jeton d'accès
      - TODO par signature (uniquement pour les jetons JWT)
      - la validation par introspection est lancée à l'initiative de l'opérateur
      
    mpham 29/09/2022
    mpham 14/12/2022 on ne lance plus une introspection inconditionnelle
    """
    
    if request['validation_method'] == 'signature':
      #self.verify_access_token_signature(request, access_token)
      pass
    elif request['validation_method'] != 'none' and request['validation_method'] != 'introspection':
      raise AduneoError(self.log_error('Access token validation method '+request['validation_method']+' unknown'))

  
  @register_url(method='GET')
  def introspection_spa(self):
    """ Prépare une requête d'introspection (RFC 7662) du jeton d'accès courant
    
      Le jeton est récupéré du contexte, dans le champ tokens/access_token
      
      La requête est transmise à send_introspection_request_spa pour exécution
    
      mpham 15/12/2022
    """
    
    access_token = None
    self.start_result_table()
    try:

      self.log_info('Introspection')

      # récupération de context_id pour obtention des paramètres dans la session
      context_id = self.get_query_string_param('contextid')
      self.log_info(('  ' * 1)+'for context: '+context_id)
      context = self.get_session_value(context_id)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      tokens = context.get('tokens')
      if (tokens is None):
        raise AduneoError(self.log_error('tokens not found in session'))

      access_token = tokens.get('access_token')
      if not access_token:
        raise AduneoError(self.log_error('Access token not found'))
      self.log_info(('  ' * 1)+'with access token '+access_token)
  
      introspection_endpoint = '' # Cas où l'introspection se fait depuis la page OIDC ou depuis SAML après un échange assertion SAML -> access token
      if 'meta_data' in context:
        # Cas général
        introspection_endpoint = context['meta_data']['introspection_endpoint']

      request = context['request']
        
      self.display_form_http_request(
        method = 'POST', 
        url = introspection_endpoint, 
        table = {
          'title': 'Introspection',
          'fields': [
            {'name': 'token', 'label': 'Token', 'help_id': 'introspection_token', 'clipboard_category': 'access_token', 'type': 'edit_text', 'value': access_token},
            {'name': 'token_type_hint', 'label': 'Token type hint', 'help_id': 'introspection_token_type_hint', 'type': 'edit_text', 'value': ''},
            ]
          },
        data_generator = """
          let data = {};
          ['token', 'token_type_hint'].forEach(function(field, index) {
            let value = get_form_value_with_dom(domId, field);
            if (value != '') {
              data[field] = value;
            }
          });
          return data;
        """, 
        http_parameters = {
          'url_label': 'Introspection endpoint', 
          'url_clipboard_category': 'introspection_endpoint',
          'auth_method': request.get('token_endpoint_auth_method', 'POST'),
          'auth_login': request.get('rs_client_id', ''),
          },
        sender_url = '/client/oauth/login/send_introspection_request_spa',
        context = context_id,
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on')),
        )
          
    except AduneoError as error:
      self.add_content('<h4>Introspection error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Introspection error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()


  @register_url(method='POST')
  def send_introspection_request_spa(self):
    """ Introspection du jeton d'accès courant, d'après une requête d'introspection préparée par introspection_spa
    
      La requête en elle-même est exécutée par BaseHandler.send_form_http_request
      
      mpham 15/12/2022
    """

    self.start_result_table()
    try:

      state = self.post_form.get('context')
      if state is None:
        raise AduneoError(self.log_error("tracking identifier (state) not found in request"))
      self.log_info("  for state "+state)
      
      context = self.get_session_value(state)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      if 'rs_client_secret!' not in request:
        if context['initial_flow']['flow_type'] == 'OAuth2':
          rp = self.conf['oauth_clients'][context['initial_flow']['app_id']]
          request['rs_client_secret!'] = rp.get('rs_client_secret!')
      
      self.log_info("Submitting introspection request")
      r = self.send_form_http_request(default_secret=request.get('rs_client_secret!', ''))
      response = r.json()

      self.log_info('Introspection response'+json.dumps(response, indent=2))
      self.add_result_row('Introspection response', json.dumps(response, indent=2), 'introspection_response')
      
      token_state = {True: 'active token', False: 'inactive token'}[response.get('active', False)]
      self.log_info('Token state'+token_state)
      self.add_result_row('Token state', token_state, 'token_state')
      
      if not response.get('active', False):
        raise AduneoError(self.log_error('token is not active '))
      
      self.end_result_table()
      self.add_content('<h4>Authorization successful</h4>')
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h3>Token introspection failed: '+html.escape(str(error))+'</h3>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Token introspection failed: '+html.escape(str(error))+'</h3>')

    self._add_footer_menu(context) 
      
    self.send_page_raw()


  @register_url(url='refreshtoken_spa', method='GET')
  def refresh_token_spa(self):
    """ Prépare une requête de rafraîchissement de jeton (RFC 6749 - section 6)
      
      Le jeton de rafraîchissement courant est récupéré du contexte, dans le champ tokens/refresh_token
      
      La requête est envoyée à send_refresh_token_request_spa pour exécution
    
    Versions:
      23/12/2022 (mpham) : version initiale
    """
    
    try:

      self.log_info('Refreshing an Access Token (RFC 6749)')

      # récupération de contextid pour obtention des paramètres dans la session
      context_id = self.get_query_string_param('contextid')
      self.log_info(('  ' * 1)+'for context: '+context_id)
      
      context = self.get_session_value(context_id)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      tokens = context.get('tokens')
      if (tokens is None):
        raise AduneoError(self.log_error('tokens not found in session'))
        
      refresh_token = tokens.get('refresh_token')
      if not refresh_token:
        raise AduneoError(self.log_error('Refresh token not found'))
      self.log_info(('  ' * 1)+'with refresh token '+refresh_token)

      token_endpoint = context['meta_data']['token_endpoint']
      self.log_info(('  ' * 1)+'token endpoint: '+token_endpoint)
        
      self.display_form_http_request(
        method = 'POST', 
        url = token_endpoint,
        table = {
          'title': 'Refresh token',
          'fields': [
            {'name': 'grant_type', 'label': 'Grant type', 'help_id': 'refresh_tk_grant_type', 'type': 'display_text', 'value': 'refresh_token'},
            {'name': 'refresh_token', 'label': 'Refresh token', 'help_id': 'refresh_tk_refresh_token', 'type': 'edit_text', 'value': refresh_token},
            {'name': 'scope', 'label': 'Scope', 'help_id': 'refresh_tk_scope', 'type': 'edit_text', 'value': request.get('scope', '')},
            ]
          },
        data_generator = """
          let data = {'grant_type': 'refresh_token'};
          ['refresh_token', 'scope'].forEach(function(field, index) {
            let value = get_form_value_with_dom(domId, field);
            if (value != '') {
              data[field] = value;
            }
          });
          return data;
        """, 
        http_parameters = {
          'url_label': 'Token endpoint',
          'url_clipboard_category': 'token_endpoint',
          'auth_method': request.get('token_endpoint_auth_method', 'POST'),
          'auth_login': request.get('client_id', ''),
          },
        sender_url = '/client/oauth/login/send_refresh_token_request_spa',
        context = request['state'],
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on')),
        )
          
    except AduneoError as error:
      self.add_content('<h4>Refresh token error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Refresh token error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
      
        
  @register_url(method='POST')
  def send_refresh_token_request_spa(self):
    """ Rafraîchissement d'un jeton, d'après une requête d'échange préparée par refresh_token_spa
    
      La requête en elle-même est exécutée par FlowHandler.send_form_http_request
      
    Versions:
      23/12/2022 (mpham) : version initiale
    """

    self.start_result_table()
    try:

      context_id = self.post_form.get('context')
      if context_id is None:
        raise AduneoError(self.log_error("tracking identifier (context id) not found in request"))
      self.log_info("  for context id "+context_id)
      
      context = self.get_session_value(context_id)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      if 'client_secret!' not in request:
        rp = self.conf['oauth_clients'][request['rp_id']]
        request['client_secret!'] = rp.get('client_secret!')
      
      self.log_info("Submitting refresh token request")
      r = self.send_form_http_request(default_secret=request['client_secret!'])
      
      response = r.json()
      self.log_info('AS response:')
      self.log_info(json.dumps(response, indent=2))
      self.add_result_row('Raw AS response', json.dumps(response, indent=2), 'as_raw_response')

      if 'tokens' not in context:
        context['tokens'] = {}
        
      if 'access_token' not in response:
        raise AduneoError(self.log_error('access token not found in response'))
      access_token = response['access_token']
      self.add_result_row('Access token', access_token, 'access_token')
      context['tokens']['access_token'] = access_token
      
      if 'refresh_token' in response:
        refresh_token = response['refresh_token']
        self.add_result_row('Refresh token', refresh_token, 'refresh_token')
        context['tokens']['refresh_token'] = refresh_token
      
      self.end_result_table()
      
      self.set_session_value(context_id, context)
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h3>Refresh token failed: '+html.escape(str(error))+'</h3>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Refresh token failed: '+html.escape(str(error))+'</h3>')

    self._add_footer_menu(context) 
      
    self.send_page_raw()


  @register_url(url='tokenexchange_spa', method='GET')
  def token_exchange_spa(self):
    """ Prépare une requête de Token Exchange (RFC 8693)
      
      Le jeton d'accès courant est récupéré du contexte, dans le champ tokens/access_token
      
      La requête est envoyée à send_token_exchange_request_spa pour exécution
    
    Versions:
      15/12/2022 (mpham) : version initiale
      28/12/2022 (mpham) : échange de jeton d'identité
    """
    
    try:

      self.log_info('Token exchange')
      
      # récupération de state pour obtention des paramètres dans la session
      context_id = self.get_query_string_param('contextid')
      self.log_info(('  ' * 1)+'for context: '+context_id)
      
      context = self.get_session_value(context_id)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      tokens = context.get('tokens')
      if (tokens is None):
        raise AduneoError(self.log_error('tokens not found in session'))

      token_type = self.get_query_string_param('token_type')
      if not token_type:
        raise AduneoError(self.log_error("token type not found in query string"))
      
      token = None
      subject_token_type = None
      if token_type == 'access_token':
        token = tokens.get('access_token')
        if not token:
          raise AduneoError(self.log_error('Access token not found'))
        subject_token_type = 'urn:ietf:params:oauth:token-type:access_token'
        self.log_info(('  ' * 1)+'with access token '+token)
      elif token_type == 'id_token':
        token = tokens.get('id_token')
        if not token:
          raise AduneoError(self.log_error('ID token not found'))
        subject_token_type = 'urn:ietf:params:oauth:token-type:id_token'
        self.log_info(('  ' * 1)+'with ID token '+token)
      else:
        raise AduneoError(self.log_error("token type "+token_type+" unsupported"))

      token_endpoint = '' # Cas où l'échange se fait depuis la page OIDC ou depuis SAML après un échange assertion SAML -> access token
      if 'meta_data' in context:
        # Cas général
        token_endpoint = context['meta_data']['token_endpoint']
      self.log_info(('  ' * 1)+'token endpoint: '+token_endpoint)
        
      self.display_form_http_request(
        method = 'POST', 
        url = token_endpoint,
        table = {
          'title': 'Token exchange',
          'fields': [
            {'name': 'grant_type', 'label': 'Grant type', 'help_id': 'tk_exch_grant_type', 'type': 'display_text', 'value': 'urn:ietf:params:oauth:grant-type:token-exchange'},
            {'name': 'requested_token_type', 'label': 'Requested token type', 'help_id': 'tk_exch_requested_token_type', 'type': 'edit_text', 'value': 'urn:ietf:params:oauth:token-type:access_token'},
            {'name': 'subject_token', 'label': 'Subject token', 'help_id': 'tk_exch_subject_token', 'type': 'edit_text', 'value': token},
            {'name': 'subject_token_type', 'label': 'Subject token type', 'help_id': 'tk_exch_subject_token_type', 'type': 'edit_text', 'value': subject_token_type},
            {'name': 'resource', 'label': 'Resource', 'help_id': 'tk_exch_resource', 'type': 'edit_text', 'value': ''},
            {'name': 'audience', 'label': 'Audience', 'help_id': 'tk_exch_audience', 'type': 'edit_text', 'value': ''},
            {'name': 'scope', 'label': 'Scope', 'help_id': 'exchange_scope', 'type': 'edit_text', 'value': request.get('scope', '')},
            {'name': 'actor_token', 'label': 'Actor token', 'help_id': 'tk_exch_actor_token', 'type': 'edit_text', 'value': ''},
            {'name': 'actor_token_type', 'label': 'Actor token type', 'help_id': 'tk_exch_actor_token_type', 'type': 'edit_text', 'value': ''},
            {'name': 'client_id', 'label': 'Client ID', 'help_id': 'tk_exch_client_id', 'type': 'edit_text', 'value': request.get('client_id', '')},
            ]
          },
        data_generator = """
          let data = {'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange'};
          ['requested_token_type', 'subject_token', 'subject_token_type', 'resource', 'audience', 'scope', 'actor_token', 'actor_token_type', 'client_id'].forEach(function(field, index) {
            let value = get_form_value_with_dom(domId, field);
            if (value != '') {
              data[field] = value;
            }
          });
          return data;
        """, 
        http_parameters = {
          'url_label': 'Token endpoint',
          'url_clipboard_category': 'token_endpoint',
          'auth_method': request.get('token_endpoint_auth_method', 'POST'),
          'auth_login': request.get('client_id', ''),
          },
        sender_url = '/client/oauth/login/send_token_exchange_request_spa',
        context = context_id,
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on')),
        )
          
    except AduneoError as error:
      self.add_content('<h4>Token exchange error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Token exchange error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
      
        
  @register_url(method='POST')
  def send_token_exchange_request_spa(self):
    """ Echange d'un jeton, d'après une requête d'échange préparée par token_exchange_spa
    
      La requête en elle-même est exécutée par FlowHandler.send_form_http_request
      
      mpham 15/12/2022
    """

    self.start_result_table()
    try:

      state = self.post_form.get('context')
      if state is None:
        raise AduneoError(self.log_error("tracking identifier (state) not found in request"))
      self.log_info("  for state "+state)
      
      context = self.get_session_value(state)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      if 'client_secret!' not in request:
        request['client_secret!'] = ''
        if context['initial_flow']['flow_type'] == 'OAuth2':
          rp = self.conf['oauth_clients'][context['initial_flow']['app_id']]
          request['client_secret!'] = rp.get('client_secret!')
      
      self.log_info("Submitting token exchange request")
      r = self.send_form_http_request(default_secret=request['client_secret!'])
      
      response = r.json()
      self.log_info('AS response:')
      self.log_info(json.dumps(response, indent=2))
      self.add_result_row('Raw AS response', json.dumps(response, indent=2), 'as_raw_response')

      if 'access_token' not in response:
        raise AduneoError(self.log_error('token not found in response'))
      token = response['access_token']
      
      if 'tokens' not in context:
        context['tokens'] = {}
        
      if 'issued_token_type' not in response:
        raise AduneoError(self.log_error('issued token type not found in response'))

      issued_token_type = response['issued_token_type']
      if issued_token_type == 'urn:ietf:params:oauth:token-type:access_token':
        self.add_result_row('Access token', token, 'access_token')
        context['tokens']['access_token'] = token
      elif issued_token_type == 'urn:ietf:params:oauth:token-type:id_token':
        self.add_result_row('ID token', token, 'id_token')
        context['tokens']['id_token'] = token
      else:
        self.add_result_row('Token', token, 'other_token')
      
      self.end_result_table()
      
      self.set_session_value(state, context)
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h3>Token exchange failed: '+html.escape(str(error))+'</h3>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Token exchange failed: '+html.escape(str(error))+'</h3>')

    self._add_footer_menu(context) 
      
    self.send_page_raw()

  
    
    
    
    


