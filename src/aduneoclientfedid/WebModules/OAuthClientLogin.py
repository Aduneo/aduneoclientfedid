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

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url
from ..Configuration import Configuration
from ..Help import Help
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler
import base64
import urllib
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
import urllib.parse

"""
  Un contexte de chaque cinématique est conservé dans la session.
    Ce contexte est compatible avec OpenID Connect et SAML, afin de réaliser des échanges de jetons
    
    Ce contexte est indexé par un identifiant unique à la cinmatique, ce qui permet à un même ordinateur de suivre plusieurs cinématiques en parallèle
    Cet index est le state, que l'on récupère donc en retour d'IdP
    
    Le contexte en lui-même est composé d'une partie commune SAML/OIDC/OAuth et d'une partie spécifique OAuth 2
    
    Contexte commun :
    "context_id": "<state (l'index de la session)>"
    "initial_flow": {
      "app_id": "<identifiant du client ClientFedID>",
      "flow_type": "OAuth2",
    }
    "tokens": {
      "saml_assertion": "<XML>",
      "access_token": "<access_token>",
      "id_token": "<id_token>"
    }
    
    Contexte spécifique :
    "request": {
      (éléments de la requête)
    }
    "meta_data": {
      (informations sur l'AS - endpoints en particulier)
    }
    
"""


@register_web_module('/client/oauth/login')
class OAuthClientLogin(FlowHandler):
 
  @register_url(url='preparerequest', method='GET')
  def prepare_request(self):

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


  @register_url(url='sendrequest', method='POST')
  def send_request(self):
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
  def callback(self):
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
      self.add_content('<h3>Token exchange failed: '+html.escape(str(error))+'</h3>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Token exchange failed: '+html.escape(str(error))+'</h3>')

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

  
    
    
    
    


