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
from ..Explanation import Explanation
from ..Help import Help
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler
import base64
import datetime
import html
import json
import jwcrypto.jwt
import requests
import traceback
import uuid

"""
  TODO : si signature HMAC (HS256 dans l'alg de l'en-tête de l'ID Token), il faut utiliser le secret (encodé en UTF-8 puis en base 64) comme clé
         voir le code France Connect
         Fait, mais maintenant il faut être compatible avec HS512, etc.
  TODO : LemonLDAP renvoie un tableau pour l'audience (In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.)
"""

"""
  Un contexte de chaque cinématique est conservé dans la session.
    Ce contexte est compatible avec OpenID Connect et SAML, afin de réaliser des échanges de jetons
    
    Ce contexte est indexé par un identifiant unique à la cinmatique, ce qui permet à un même ordinateur de suivre plusieurs cinématiques en parallèle
    Cet index est le state, que l'on récupère donc en retour d'IdP
    
    Le contexte en lui-même est composé d'une partie commune SAML/OIDC/OAuth et d'une partie spécifique OpenID Connect
    
    Contexte commun :
    "context_id": "<state (l'index de la session)>"
    "initial_flow": {
      "app_id": "<identifiant du client ClientFedID>",
      "flow_type": "OIDC",
    }
    "tokens": {
      "saml_assertion": "<XML>",
      "access_token": "<access_token>",
      "id_token": "<id_token>",
      "op_access_token": "<access_token pour autorisation auprès des endpoint de l'OP - par exemple userinfo>",
    }
    
    Contexte spécifique :
    "request": {
      (éléments de la requête)
    }
    "meta_data": {
      (informations sur l'OP - endpoints en particulier)
    }
    
"""


@register_web_module('/client/oidc/login')
class OIDCClientLogin(FlowHandler):
 
  @register_url(url='preparerequest', method='GET')
  def prepare_request(self):

    """
      Prépare la requête d'authentification OIDC

    Versions:
      26/02/2021 - 05/03/2021 (mpham) : version initiale
      09/12/2022 (mpham) : ajout de token_endpoint_auth_method
      23/12/2022 (mpham) : passage en mode SPA et menu de pied de page commun
      22/02/2023 (mpham) : on retire les références à fetch_userinfo car l'appel à userinfo est maintenant manuel
    """

    self.log_info('--- Start OIDC flow ---')

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
        rp = self.conf['oidc_clients'][rp_id]
        self.log_info(('  ' * 1)+'for OP '+rp['name'])

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
      
      conf_rp = self.conf['oidc_clients'][rp_id]
      rp['name'] = conf_rp['name']
      meta_data = context['meta_data']
      self.log_info(('  ' * 1)+'for OP '+rp['name'])
    
    self.add_content("<h1>OIDC Client: "+rp["name"]+"</h1>")
    
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    
    self.add_content('<form name="request" action="sendrequest" method="post">')
    self.add_content('<input name="rp_id" value="'+html.escape(rp_id)+'" type="hidden" />')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>'+self.row_label('Authorization Endpoint', 'authorization_endpoint')+'</td><td><input name="authorization_endpoint" value="'+html.escape(meta_data['authorization_endpoint'])+'"class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Token endpoint', 'token_endpoint')+'</td><td><input name="token_endpoint" value="'+html.escape(meta_data['token_endpoint'])+'"class="intable" type="text"></td></tr>')

    # configuration de la clé de vérification de signature
    self.add_content('<tr id="signature_key_configuration"><td>'+self.row_label('Signature key configuration', 'signature_key_configuration')+'</td><td><select name="signature_key_configuration" class="intable" onchange="changeSignatureKeyConfiguration()">')
    for value in ('JWKS URI', 'Local configuration'):
      selected = ''
      if value.casefold() == rp.get('signature_key_configuration', 'JWKS URI').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</td></tr>')
    
    # clé de signature récupérée par JWKS
    key_visible = (rp.get('signature_key_configuration', 'JWKS URI').casefold() == 'jwks uri')
    key_visible_style = 'none'
    if key_visible:
      key_visible_style = 'table-row'
    self.add_content('<tr id="jwks_uri" style="display: '+key_visible_style+';"><td>'+self.row_label('JWKS URI', 'jwks_uri')+'</td><td><input name="jwks_uri" value="'+html.escape(meta_data.get('jwks_uri', ''))+'" class="intable" type="text"></td></tr>')
    
    # clé de signature dans le fichier local
    key_visible = (rp.get('signature_key_configuration', 'JWKS URI').casefold() == 'local configuration')
    key_visible_style = 'none'
    if key_visible:
      key_visible_style = 'table-row'
    self.add_content('<tr id="signature_key" style="display: '+key_visible_style+';"><td>'+self.row_label('Signature key', 'signature_key')+'</td><td><input name="signature_key" value="'+html.escape(meta_data.get('signature_key', ''))+'" class="intable" type="text"></td></tr>')
    
    self.add_content('<tr><td>'+self.row_label('UserInfo endpoint', 'userinfo_endpoint')+'</td><td><input name="userinfo_endpoint" value="'+html.escape(meta_data.get('userinfo_endpoint', ''))+'"class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Issuer', 'issuer')+'</td><td><input name="issuer" value="'+html.escape(meta_data.get('issuer', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Scope', 'scope')+'</td><td><input name="scope" value="'+html.escape(rp['scope'])+'" class="intable" type="text"></td></tr>')
    
    self.add_content('<tr><td>'+self.row_label('Reponse type', 'response_type')+'</td><td><select name="response_type" class="intable">')
    for value in ['code']:
      selected = ''
      if value == rp.get('response_type', ''):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')
    
    self.add_content('<tr><td>'+self.row_label('Client ID', 'client_id')+'</td><td><input name="client_id" value="'+html.escape(rp['client_id'])+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Client secret', 'client_secret')+'</td><td><input name="client_secret!" class="intable" type="password"></td></tr>')

    self.add_content('<tr><td>'+self.row_label('Token endpoint auth method', 'token_endpoint_auth_method')+'</td><td><select name="token_endpoint_auth_method" class="intable">')
    for value in ['Basic', 'POST']:
      selected = ''
      if value.casefold() == rp.get('token_endpoint_auth_method', 'POST').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    self.add_content('<tr><td>'+self.row_label('Redirect URI', 'redirect_uri')+'</td><td><input name="redirect_uri" value="'+html.escape(rp.get('redirect_uri', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('State', 'state')+'</td><td>'+html.escape(state)+'</td></tr>')
    self.add_content('<tr><td>'+self.row_label('Nonce', 'nonce')+'</td><td><input name="nonce" value="'+html.escape(nonce)+'" class="intable" type="text"></td></tr>')

    self.add_content('<tr><td>'+self.row_label('Display', 'display')+'</td><td><select name="display" class="intable">')
    for value in ('', 'page', 'popup', 'touch', 'wap'):
      selected = ''
      if value == rp.get('display', ''):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    self.add_content('<tr><td>'+self.row_label('Prompt', 'prompt')+'</td><td><select name="prompt" class="intable">')
    for value in ('', 'none', 'login', 'consent', 'select_account'):
      selected = ''
      if value == rp.get('prompt', ''):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    self.add_content('<tr><td>'+self.row_label('Max age', 'max_age')+'</td><td><input name="max_age" value="'+html.escape(rp.get('max_age', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('UI locales', 'ui_locales')+'</td><td><input name="ui_locales" value="'+html.escape(rp.get('ui_locales', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('ID token hint', 'id_token_hint')+'</td><td><input name="id_token_hint" value="'+html.escape(rp.get('id_token_hint', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Login hint', 'login_hint')+'</td><td><input name="login_hint" value="'+html.escape(rp.get('login_hint', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('ACR values', 'acr_values')+'</td><td><input name="acr_values" value="'+html.escape(rp.get('acr_values', ''))+'" class="intable" type="text"></td></tr>')
    
    self.add_content('</table>')

    self.add_content("<h2>Non OIDC Options</h2>")
    self.add_content('<table class="fixed">')
    checked = ''
    if Configuration.is_on(rp.get('verify_certificates', 'off')):
      checked = ' checked'
    self.add_content('<tr><td>'+self.row_label('Certificate verification', 'verify_certificates')+'</td><td><input name="verify_certificates" type="checkbox"'+checked+'></td></tr>')
    self.add_content('</table>')
    
    self.add_content('<div style="padding-top: 20px; padding-bottom: 12px;"><div style="padding-bottom: 6px;"><strong>Authentication request</strong> <img title="Copy request" class="smallButton" src="/images/copy.png" onClick="copyRequest()"/></div>')
    self.add_content('<span id="auth_request" style="font-size: 14px;"></span></div>')
    self.add_content('<input name="authentication_request" type="hidden">')
    self.add_content('<input name="state" value="'+html.escape(state)+'" type="hidden">')
    
    self.add_content('<button type="submit" class="button" onclick="openConsole();">Send to IdP</button>')
    self.add_content('</form>')

    self.add_content("""
    <script>

    window.addEventListener('load', (event) => {
      if (document.request.redirect_uri.value == '') {
        document.request.redirect_uri.value = window.location.origin + '/client/oidc/login/callback';
      }
    });
    
    function updateAuthRequest() {
      var request = document.request.authorization_endpoint.value
        + '?scope='+encodeURIComponent(document.request.scope.value);
      ['response_type', 'client_id', 'redirect_uri', 'state'].forEach(function(item, index) {
        request += '&'+item+'='+encodeURIComponent(document.request[item].value)
      });
      ['nonce', 'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values'].forEach(function(item, index) {
        if (document.request[item].value != '') { request += '&'+item+'='+encodeURIComponent(document.request[item].value); }
      });
      
      document.getElementById('auth_request').innerHTML = request;
      document.request.authentication_request.value = request;
    }
    var input = document.request.getElementsByTagName('input');
    Array.prototype.slice.call(input).forEach(function(item, index) {
      if (item.type == 'text') { item.addEventListener("input", updateAuthRequest); }
    });
    var select = document.request.getElementsByTagName('select');
    Array.prototype.slice.call(select).forEach(function(item, index) {
      if (item.name != 'signature_key_configuration') {
        item.addEventListener("change", updateAuthRequest);
      }
    });
    updateAuthRequest();

    function copyRequest() {
      copyTextToClipboard(document.request.authentication_request.value);
    }
    function copyTextToClipboard(text) {
      var tempArea = document.createElement('textarea')
      tempArea.value = text
      document.body.appendChild(tempArea)
      tempArea.select()
      tempArea.setSelectionRange(0, 99999)
      document.execCommand("copy")
      document.body.removeChild(tempArea)
    }
    
    function changeSignatureKeyConfiguration() {
      if (document.request.signature_key_configuration.value == 'JWKS URI') {
        document.getElementById('jwks_uri').style.display = 'table-row';
        document.getElementById('signature_key').style.display = 'none';
      } else {
        document.getElementById('jwks_uri').style.display = 'none';
        document.getElementById('signature_key').style.display = 'table-row';
      }
    }
    </script>
    """)
  
    self.add_content(Help.help_window_definition())
    
    self.send_page()


  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    
    """
    Récupère les informations saisies dans /oidc/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oidc/client/preparerequest et placée dans le paramètre authentication_request
    
    Versions:
      26/02/2021 - 28/02/2021 (mpham) : version initiale
      09/12/2022 (mpham) : ajout de token_endpoint_auth_method
      23/12/2022 (mpham) : passage en mode SPA et menu de pied de page commun
      22/02/2023 (mpham) : on retire les références à fetch_userinfo car l'appel à userinfo est maintenant manuel
    """
    
    self.log_info('Redirection to IdP requested')
    state = self.post_form['state']

    rp_id = self.post_form['rp_id']
    context = {"context_id": state, "initial_flow": {"app_id": rp_id, "flow_type": "OIDC"}, "request": {}, "tokens": {}}
    
    meta_data = {}
    for item in ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'jwks_uri', 'issuer', 'signature_key']:
      if self.post_form[item] != '':
        meta_data[item] = self.post_form[item]

    context['meta_data'] = meta_data
    
    request = {}
    context['request'] = request
    for item in ['rp_id', 'state', 'scope', 'response_type', 'client_id', 'client_secret!', 'token_endpoint_auth_method', 'redirect_uri', 'state', 'nonce', 'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values', 'signature_key_configuration', ]:
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
      Retour de redirection de l'OpenID Provider (OP), après l'authentification initiale de l'utilisateur
      
      Initialise la page d'échange en Javascript qui va accueillir les échanges ultérieures (introspection, token exchange)
        Cette page fait un appel aux API du client de fédération par XHR et ajoute le HTML retourné dans la page
        
        Ca permet de rester sur la même page tout en faisant des interactions avec l'AS
      
      mpham 23/12/2022
    """

    self.log_info('Callback from OpenID Provider. Query string: '+self.hreq.path)
    self.log_info('Query string: '+self.hreq.path)

    self.add_content(Help.help_window_definition())
    self.add_content(Clipboard.get_window_definition())
    self.add_content("""
    <script src="/javascript/resultTable.js"></script>
    <script src="/javascript/requestSender.js"></script>
    <div id="text_ph"></div>
    <div id="end_ph"></div>
    
    <script>
    getHtml("GET", "/client/oidc/login/callback_spa"+window.location.search, 'GET')
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
    
    context = None
    self.start_result_table()
    try:
    
      self.log_info('Checking authentication')
      
      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      self.log_info('for state: '+idp_state)
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')

      context = self.get_session_value(idp_state)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))
      
      request = context.get('request')
      if (request is None):
        raise AduneoError(self.log_error('request not found in session'))

      # extraction des informations utiles de la session
      rp_id = request['rp_id']
      meta_data = context['meta_data']
      token_endpoint = meta_data['token_endpoint']
      client_id = request['client_id']
      redirect_uri = request['redirect_uri']
      
      if 'client_secret!' in request:
        client_secret = request['client_secret!']
      else:
        # il faut aller chercher le mot de passe dans la configuration
        rp = self.conf['oidc_clients'][rp_id]
        client_secret = rp['client_secret!']

      token_endpoint_auth_method = request['token_endpoint_auth_method'].casefold()

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
      if token_endpoint_auth_method == 'basic':
        auth = (client_id, client_secret)
      elif token_endpoint_auth_method == 'post':
        data['client_secret'] = client_secret
      else:
        raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be Basic or POST')
      
      self.add_result_row('Token endpoint', token_endpoint, 'token_endpoint')
      self.add_content('<tr><td>Retrieving tokens...</td>')
      self.log_info("Starting token retrieval")
      try:
        self.log_info("Connecting to "+token_endpoint)
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        # Remarque : ici on est en authentification client_secret_post alors que la méthode par défaut, c'est client_secret_basic (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
        r = requests.post(token_endpoint, data=data, auth=auth, verify=verify_certificates)
      except Exception as error:
        self.add_content('<td>Error : '+str(error)+'</td><td></td></tr>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_content('<td>OK</td><td></td></tr>')
      else:
        self.add_content('<td>Error, status code '+str(r.status_code)+'</td></tr>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status_code)+", "+r.text))

      response = r.json()
      self.log_info("IdP response:")
      self.log_info(json.dumps(response, indent=2))
      id_token = response['id_token']
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
      session_nonce = request['nonce']
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
      if 'issuer' not in meta_data:
        raise AduneoError("Issuer missing in authentication configuration", explanation_code='oidc_missing_issuer')
      if token_issuer == meta_data['issuer']:
        self.log_info("Token issuer verification OK: "+token_issuer)
        self.add_result_row('Issuer verification', 'OK: '+token_issuer, 'issuer_verification')
      else:
        self.log_error(('  ' * 1)+"Expiration verification failed:")
        self.log_error(('  ' * 2)+"Token issuer   : "+token_issuer)
        self.log_error(('  ' * 2)+"Metadata issuer: "+meta_data['issuer'])
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
        token_key = jwcrypto.jwk.JWK(**key)

      else:
        # Signature asymétrique
        self.log_info('Asymmetric signature, fetching public key')
      
        # On regarde si on doit aller chercher les clés avec l'endpoint JWKS ou si la clé a été donnée localement
        if request['signature_key_configuration'] == 'Local configuration':
          self.log_info('Signature JWK:')
          self.log_info(meta_data['signature_key'])
          token_jwk = json.loads(meta_data['signature_key'])
        else:
        
          # On extrait l'identifiant de la clé depuis l'id token
          idp_kid = token_header['kid']
          self.log_info('Signature key kid: '+idp_kid)
          self.add_result_row('Signature key kid', idp_kid, 'signature_key_kid')
          
          # on va chercher la liste des clés
          self.log_info("Starting IdP keys retrieval")
          self.add_result_row('JWKS endpoint', meta_data['jwks_uri'], 'jwks_endpoint')
          self.add_content('<tr><td>Retrieving keys...</td>')
          try:
            verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
            self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
            r = requests.get(meta_data['jwks_uri'], verify=verify_certificates)
          except Exception as error:
            self.add_content('<td>Error : '+str(error)+'</td><td></td></tr>')
            raise AduneoError(self.log_error(('  ' * 2)+'IdP keys retrieval error: '+str(error)))
          if r.status_code == 200:
            self.add_content('<td>OK</td><td></td></tr>')
          else:
            self.add_content('<td>Error, status code '+str(r.status_code)+'</td></tr>')
            raise AduneoError(self.log_error('IdP keys retrieval error: status code '+str(r.status_code)))

          keyset = r.json()
          self.log_info("IdP response:")
          self.log_info(json.dumps(keyset, indent=2))
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
        token_key = jwcrypto.jwk.JWK(**token_jwk)

      # On vérifie la signature
      try:
        jwcrypto.jwt.JWT(key=token_key, jwt=id_token)
        self.log_info('Signature verification OK')
        self.add_result_row('Signature verification', 'OK', copy_button=False)
      except Exception as error:

        default_case = True
        # Si on est en HS256, peut-être que le serveur a utilisé une clé autre que celle du client_secret (cas Keycloak)
        if alg == 'HS256':
          if request['signature_key_configuration'] != 'Local configuration':
            self.log_info('HS256 signature, client_secret not working. The server might have used another key. Put this key in configuration')
          else:
            default_case = False
            self.log_info('HS256 signature, client_secret not working, trying key from configuration')
            
            configuration_key = meta_data['signature_key']
            self.log_info('Configuration key:')
            self.log_info(configuration_key)
            json_key = json.loads(configuration_key)
          
            token_key = jwcrypto.jwk.JWK(**json_key)
          
            try:
              jwcrypto.jwt.JWT(key=token_key, jwt=id_token)
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
      self.add_content('<h3>Authentication succcessful</h3>')
      
      # Enregistrement des jetons dans la session pour manipulation ultérieure
      context['tokens'] = {'id_token': id_token}
      if op_access_token:
        context['tokens']['op_access_token'] = op_access_token

      self.set_session_value(request['state'], context)

      # on considère qu'on est bien loggé
      self.logon('oidc_client_'+rp_id, id_token)

    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h4>Authentication failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_content(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Authentication failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End OpenID Connect flow ---')

    self._add_footer_menu(context) 

    self.send_page_raw()


  @register_url(method='GET')
  def userinfo_spa(self):
    """ Prépare une requête userinfo du jeton d'identité courant

      On a uniquement besoin de l'AT de l'OP, dans le champ tokens/op_access_token
      
      La requête est transmise à send_inserinnfo_request_spa pour exécution
    
      Versions:
        23/12/2022 (mpham) : version initiale
        22/02/2023 (mpham) : on passe en GET au lieu de POST (recommandation des spécifications)
        23/02/2023 (mpham) : possibilité de choisir GET ou POST
    """
    
    self.start_result_table()
    try:

      self.log_info('Userinfo')

      # récupération de context_id pour obtention des paramètres dans la session
      context_id = self.get_query_string_param('contextid')
      self.log_info(('  ' * 1)+'for context: '+context_id)
      context = self.get_session_value(context_id)
      if (context is None):
        raise AduneoError(self.log_error('context not found in session'))

      tokens = context.get('tokens')
      if (tokens is None):
        raise AduneoError(self.log_error('tokens not found in session'))

      op_access_token = tokens.get('op_access_token')
      if not op_access_token:
        raise AduneoError(self.log_error('Access token for OP not found'))
      self.log_info(('  ' * 1)+'with access token '+op_access_token)
  
      userinfo_endpoint = ''
      if 'meta_data' in context:
        userinfo_endpoint = context['meta_data'].get('userinfo_endpoint', '')

      request = context['request']
        
      self.display_form_http_request(
        method = 'GET,POST', 
        url = userinfo_endpoint, 
        table = {
          'title': 'Userinfo',
          'fields': []
          },
        http_parameters = {
          'url_label': 'Userinfo endpoint',
          'url_clipboard_category': 'userinfo_endpoint',
          'auth_method': 'Bearer token',
          'auth_login': op_access_token,
          },
        sender_url = '/client/oidc/login/send_userinfo_request_spa',
        context = context_id,
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on')),
        )
          
    except AduneoError as error:
      self.add_content('<h4>Userinfo error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h4>Userinfo error: '+html.escape(str(error))+'</h4>')
      if context:
        self._add_footer_menu(context)
      self.send_json_page()


  @register_url(method='POST')
  def send_userinfo_request_spa(self):
    """ Userinfo, d'après une requête userinfo préparée par userinfo_spa
    
      La requête en elle-même est exécutée par FlowHandler.send_form_http_request
      
      Versions:
        23/12/2022 (mpham) : version initiale
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

      self.log_info("Submitting userinfo request")
      r = self.send_form_http_request()
      response = r.json()

      self.log_info('Userinfo response'+json.dumps(response, indent=2))
      self.add_result_row('Userinfo response', json.dumps(response, indent=2), 'userinfo_response')
      
      self.end_result_table()
      
    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_content('<h3>Userinfo failed: '+html.escape(str(error))+'</h3>')
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_content('<h3>Userinfo failed: '+html.escape(str(error))+'</h3>')

    self._add_footer_menu(context) 
      
    self.send_page_raw()


  def _check_authentication_deprecated(self):
    
    """
    Vérifie la bonne authentification :
    - récupère les jeton auprès de l'IdP
    - valide les jetons
    
    mpham 26/02/2021 - 28/02/2021
    mpham 09/12/2022 ajout de token_endpoint_auth_method
    """
    
    self.add_content(Help.help_window_definition())
    self.start_result_table()
    
    try:
    
      self.log_info('Checking authentication')
      
      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      self.log_info('for state: '+idp_state)
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')
      request = self.get_session_value(idp_state)
      if (request is None):
        raise AduneoError(self.log_error('state not found in session'))

      # extraction des informations utiles de la session
      rp_id = request['rp_id']
      meta_data = request['meta_data']
      token_endpoint = meta_data['token_endpoint']
      client_id = request['client_id']
      redirect_uri = request['redirect_uri']
      
      if 'client_secret!' in request:
        client_secret = request['client_secret!']
      else:
        # il faut aller chercher le mot de passe dans la configuration
        rp = self.conf['oidc_clients'][rp_id]
        client_secret = rp['client_secret!']

      token_endpoint_auth_method = request['token_endpoint_auth_method'].casefold()

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
      if token_endpoint_auth_method == 'basic':
        auth = (client_id, client_secret)
      elif token_endpoint_auth_method == 'post':
        data['client_secret'] = client_secret
      else:
        raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be Basic or POST')
      
      self.add_result_row('Token endpoint', token_endpoint, 'token_endpoint')
      self.add_content('<tr><td>Retrieving tokens...</td>')
      self.log_info("Starting token retrieval")
      try:
        self.log_info("Connecting to "+token_endpoint)
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        # Remarque : ici on est en authentification client_secret_post alors que la méthode par défaut, c'est client_secret_basic (https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)
        r = requests.post(token_endpoint, data=data, auth=auth, verify=verify_certificates)
      except Exception as error:
        self.add_content('<td>Error : '+str(error)+'</td></tr>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_content('<td>OK</td><td></td></tr>')
      else:
        self.add_content('<td>Error, status code '+str(r.status_code)+'</td></tr>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status_code)+", "+r.text))

      response = r.json()
      self.log_info("IdP response:")
      self.log_info(json.dumps(response, indent=2))
      id_token = response['id_token']
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
      session_nonce = request['nonce']
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
      if token_issuer == meta_data['issuer']:
        self.log_info("Token issuer verification OK: "+token_issuer)
        self.add_result_row('Issuer verification', 'OK: '+token_issuer, 'issuer_verification')
      else:
        self.log_error(('  ' * 1)+"Expiration verification failed:")
        self.log_error(('  ' * 2)+"Token issuer   : "+token_issuer)
        self.log_error(('  ' * 2)+"Metadata issuer: "+meta_data['issuer'])
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
        token_key = jwcrypto.jwk.JWK(**key)

      else:
        # Signature asymétrique
        self.log_info('Asymmetric signature, fetching public key')
      
        # On regarde si on doit aller chercher les clés avec l'endpoint JWKS ou si la clé a été donnée localement
        if request['signature_key_configuration'] == 'Local configuration':
          self.log_info('Signature JWK:')
          self.log_info(meta_data['signature_key'])
          token_jwk = json.loads(meta_data['signature_key'])
        else:
        
          # On extrait l'identifiant de la clé depuis l'id token
          idp_kid = token_header['kid']
          self.log_info('Signature key kid: '+idp_kid)
          self.add_result_row('Signature key kid', idp_kid, 'signature_key_kid')
          
          # on va chercher la liste des clés
          self.log_info("Starting IdP keys retrieval")
          self.add_result_row('JWKS endpoint', meta_data['jwks_uri'], 'jwks_endpoint')
          self.add_content('<tr><td>Retrieving keys...</td>')
          try:
            verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
            self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
            r = requests.get(meta_data['jwks_uri'], verify=verify_certificates)
          except Exception as error:
            self.add_content('<td>Error : '+str(error)+'</td><td></td></tr>')
            raise AduneoError(self.log_error(('  ' * 2)+'IdP keys retrieval error: '+str(error)))
          if r.status_code == 200:
            self.add_content('<td>OK</td><td></td></tr>')
          else:
            self.add_content('<td>Error, status code '+str(r.status_code)+'</td><td></td></tr>')
            raise AduneoError(self.log_error('IdP keys retrieval error: status code '+str(r.status_code)))

          keyset = r.json()
          self.log_info("IdP response:")
          self.log_info(json.dumps(keyset, indent=2))
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
        token_key = jwcrypto.jwk.JWK(**token_jwk)

      # On vérifie la signature
      try:
        jwcrypto.jwt.JWT(key=token_key, jwt=id_token)
        self.log_info('Signature verification OK')
        self.add_result_row('Signature verification', 'OK', copy_button=False)
      except Exception as error:

        default_case = True
        # Si on est en HS256, peut-être que le serveur a utilisé une clé autre que celle du client_secret (cas Keycloak)
        if alg == 'HS256':
          if request['signature_key_configuration'] != 'Local configuration':
            self.log_info('HS256 signature, client_secret not working. The server might have used another key. Put this key in configuration')
          else:
            default_case = False
            self.log_info('HS256 signature, client_secret not working, trying key from configuration')
            
            configuration_key = meta_data['signature_key']
            self.log_info('Configuration key:')
            self.log_info(configuration_key)
            json_key = json.loads(configuration_key)
          
            token_key = jwcrypto.jwk.JWK(**json_key)
          
            try:
              jwcrypto.jwt.JWT(key=token_key, jwt=id_token)
              self.log_info('Signature verification OK')
              self.add_result_row('Signature verification', 'OK', copy_button=False)
            except Exception as error:
              default_case = True
          
        if default_case:
          # Cas normal de la signature non vérifiée
          self.add_result_row('Signature verification', 'Failed', copy_button=False)
          raise AduneoError(self.log_error('Signature verification failed'))
      
      # On conserve l'access token pour userinfo
      self.log_info('Access token:')
      self.log_info(response['access_token'])
      self.access_token = response['access_token']

      # on considère qu'on est bien loggé
      self.logon('oidc_client_'+rp_id, id_token)

      
    finally:
      self.end_result_table()


  def _get_userinfo_old(self):

    self.log_info('Getting userinfo')
    self.start_result_table()

    try:

      # récupération de state pour obtention des paramètres dans la session
      idp_state = self.get_query_string_param('state')
      self.log_info('for state: '+idp_state)
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')
      request = self.get_session_value(idp_state)
      if (request is None):
        raise AduneoError(self.log_error('state not found in session'))

      # extraction des informations utiles de la session
      meta_data = request['meta_data']
      token_endpoint = meta_data['token_endpoint']
      client_id = request['client_id']
      redirect_uri = request['redirect_uri']

      # récupération UserInfo
      userinfo_endpoint = meta_data['userinfo_endpoint']
      self.log_info('Userinfo endpoint: '+userinfo_endpoint)
      self.add_result_row('Userinfo endpoint', userinfo_endpoint, 'userinfo_endpoint')
      self.add_result_row('Access token', self.access_token, 'access_token')
      
      # Décodage de l'AT si c'est un JWT (pour l'instant la vérification que c'est un JWT est sommaire et devra être affinée
      if self.access_token.startswith('eyJh'):
        self.log_info("Access token is a JWT")
        at_items = self.access_token.split('.')
        encoded_at_header = at_items[0]
        at_header_string = base64.urlsafe_b64decode(encoded_at_header + '=' * (4 - len(encoded_at_header) % 4))
        encoded_at_payload = at_items[1]
        at_payload = base64.urlsafe_b64decode(encoded_at_payload + '=' * (4 - len(encoded_at_payload) % 4))

        at_header = json.loads(at_header_string)
        self.add_result_row('Access token header', json.dumps(at_header, indent=2), 'at_header')
        self.log_info("Access token header:")
        self.log_info(json.dumps(at_header, indent=2))

        at_claims = json.loads(at_payload)
        self.add_result_row('Access token claims set', json.dumps(at_claims, indent=2), 'at_claims_set')
        self.log_info("Access token payload:")
        self.log_info(json.dumps(at_claims, indent=2))
      
      self.log_info('Starting userinfo retrieval')
      self.add_content('<tr><td>Retrieving user info...</td>')
      try:
        verify_certificates = Configuration.is_on(request.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        r = requests.get(userinfo_endpoint, headers = {'Authorization':"Bearer "+self.access_token}, verify=verify_certificates)
      except Exception as error:
        self.add_content('<td>Error : '+str(error)+'</td></tr>')
        raise AduneoError(self.log_error(('  ' * 1)+'userinfo retrieval error: '+str(error)))
      if r.status_code == 200:
        self.add_content('<td>OK</td></tr>')
      else:
        self.add_content('<td>Error, status code '+str(r.status_code)+'</td></tr>')
        raise AduneoError(self.log_error('userinfo retrieval error: status code '+str(r.status_code)))
      
      response = r.json()
      self.log_info('User info:')
      self.log_info(json.dumps(response, indent=2))
      self.add_result_row('User info', json.dumps(response, indent=2), 'user_info')
      
    finally: 
      self.end_result_table()
      self.log_info('--- End OIDC flow ---')


