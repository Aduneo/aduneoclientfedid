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
import datetime
import html
import json
import time
import traceback
import urllib.parse
import uuid

from ..BaseServer import AduneoError
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import RequesterForm
from ..Configuration import Configuration
from ..Context import Context
from ..Explanation import Explanation
from ..Help import Help
from ..JWT import JWT
from ..WebRequest import WebRequest
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler

"""
  TODO : si signature HMAC (HS256 dans l'alg de l'en-tête de l'ID Token), il faut utiliser le secret (encodé en UTF-8 puis en base 64) comme clé
         voir le code France Connect
         Fait, mais maintenant il faut être compatible avec HS512, etc.
  TODO : LemonLDAP renvoie un tableau pour l'audience (In the general case, the aud value is an array of case sensitive strings. In the common special case when there is one audience, the aud value MAY be a single case sensitive string.)
"""

"""
  Un contexte de chaque cinématique est conservé dans la session.
    Ce contexte est compatible avec OpenID Connect et SAML, afin de réaliser des échanges de jetons
    
    Ce contexte est indexé par un identifiant unique à la cinématique, ce qui permet à un même ordinateur de suivre plusieurs cinématiques en parallèle
    Cet index est le state, que l'on récupère donc en retour d'IdP
    
    Voir l'objet Context
    
    Le contexte est récupéré lors de l'initialisation de OIDCClientLogin, par le constructeur de FlowHandler
      S'il est présent, les paramètres de l'IdP et de la requête sont repris aux dernières valeurs modifiées
      Sinon elles sont récupérées de la configuration
"""


@register_web_module('/client/oidc/login')
class OIDCClientLogin(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=False)
  def prepare_request(self):
    """
      Prépare la requête d'authentification OIDC

    Versions:
      26/02/2021 - 05/03/2021 (mpham) : version initiale
      09/12/2022 (mpham) ajout de token_endpoint_auth_method
      22/02/2023 (mpham) on retire les références à fetch_userinfo car l'appel à userinfo est maintenant manuel
      24/03/2023 (mpham) passage en mode SPA
      03/08/2023 (mpham) on achève le passage en page continuous
      08/08/2024 (mpham) récriture avec RequesterForm et nouvelle configuration
      27/11/2024 (mpham) on n'envoie pas les éléments vides du formulaire (Keycloak tombe en erreur sinon)
      28/11/2024 (mpham) on modifiait l'objet de configuration, de manière permanente s'il était enregistré par la suite
      04/12/2024 (mpham) new auth : on conserve le contexte, mais on récupère les paramètres de la configuration
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
      08/06/2025 (mpham) DNS override for OIDC token and userinfo endpoints
      19/06/2025 (mpham) régression : verify_certificates qui était récupéré de oidc_idp_params au lieu de idp_params
    """

    self.log_info('--- Start OpenID Connect flow ---')

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
        oidc_idp_params = idp_params.get('oidc')
        if not oidc_idp_params:
          raise AduneoError(f"OIDC IdP configuration missing for {idp.get('name', idp_id)}", button_label="IdP configuration", action=f"/client/idp/admin/modify?idpid={idp_id}")
        app_params = idp['oidc_clients'][app_id]

        # On récupère name des paramètres de l'IdP
        idp_params['name'] = idp['name']

        # si le contexte existe, on le conserve (cas newauth)
        if self.context is None:
          self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'OIDC'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

        if oidc_idp_params.get('endpoint_configuration', 'local_configuration') == 'same_as_oauth2':
          # récupération des paramètres OIDC pour les endpoints
          oauth2_params = idp['idp_parameters'].get('oauth2')
          if not oauth2_params:
            raise AduneoError("can't retrieve endpoint parameters from OAuth 2 configuration since OAuth 2 is not configured")
          if oauth2_params.get('endpoint_configuration') == 'same_as_oauth2':
            raise AduneoError("can't retrieve endpoint parameters from OAuth 2 configuration since OAuth 2 is configured with same_as_oidc")
          for param in ['endpoint_configuration', 'metadata_uri', 'authorization_endpoint', 'token_endpoint']:
            oidc_idp_params[param] = oauth2_params.get(param, '')
          if oidc_idp_params.get('endpoint_configuration') == 'metadata_uri':
            oidc_idp_params['endpoint_configuration'] = 'discovery_uri'
            oidc_idp_params['discovery_uri'] = oauth2_params.get('metadata_uri')
        if oidc_idp_params.get('endpoint_configuration', 'local_configuration') == 'discovery_uri':
          fetch_configuration_document = True

      else:
        # Rejeu de requête (conservée dans la session)
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        oidc_idp_params = idp_params['oidc']
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for client {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>IdP {idp_params['name']} OIDC Client {app_params['name']}</h1>")

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
          self.add_html(f"""<div class="intertable">Failed. Server responded with code {status}</div>""")
          self.send_page()
          return

      
      state = str(uuid.uuid4())
      nonce = str(uuid.uuid4())

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(state, self.context['context_id'])

      form_content = {
        'contextid': self.context['context_id'],  # TODO : remplacer par hr_context ?
        'redirect_uri': app_params.get('redirect_uri', ''),
        'authorization_endpoint': oidc_idp_params.get('authorization_endpoint', ''),
        'token_endpoint': oidc_idp_params.get('token_endpoint', ''),
        'userinfo_endpoint': oidc_idp_params.get('userinfo_endpoint', ''),
        'userinfo_method': oidc_idp_params.get('userinfo_method', 'get'),
        'issuer': oidc_idp_params.get('issuer', ''),
        'signature_key_configuration': oidc_idp_params.get('signature_key_configuration', 'jwks_uri'),
        'jwks_uri': oidc_idp_params.get('jwks_uri', ''),
        'signature_key': oidc_idp_params.get('signature_key', ''),
        'token_endpoint_dns_override': oidc_idp_params.get('token_endpoint_dns_override', ''),
        'userinfo_endpoint_dns_override': oidc_idp_params.get('userinfo_endpoint_dns_override', ''),
        'client_id': app_params.get('client_id', ''),
        'scope': app_params.get('scope', ''),
        'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'basic'),
        'display': app_params.get('display', ''),
        'prompt': app_params.get('prompt', ''),
        'max_age': app_params.get('max_age', ''),
        'ui_locales': app_params.get('ui_locales', ''),
        'id_token_hint': app_params.get('id_token_hint', ''),
        'login_hint': app_params.get('login_hint', ''),
        'acr_values': app_params.get('acr_values', ''),
        'state': state,
        'nonce': nonce,
      }
      
      form = RequesterForm('oidcauth', form_content, action='/client/oidc/login/sendrequest', mode='new_page', request_url='@[authorization_endpoint]') \
        .hidden('contextid') \
        .start_section('clientfedid_params', title="ClientFedID Parameters") \
          .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri') \
        .end_section() \
        .start_section('op_endpoints', title="OP Endpoints", collapsible=True, collapsible_default=False) \
          .text('authorization_endpoint', label='Authorization Endpoint', clipboard_category='authorization_endpoint') \
          .text('token_endpoint', label='Token Endpoint', clipboard_category='token_endpoint') \
          .text('userinfo_endpoint', label='Userinfo Endpoint', clipboard_category='userinfo_endpoint') \
          .closed_list('userinfo_method', label='Userinfo Request Method', 
            values={'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
        .end_section() \
        .start_section('id_token_validation', title="ID token validation", collapsible=True, collapsible_default=False) \
          .text('issuer', label='Issuer', clipboard_category='issuer') \
          .closed_list('signature_key_configuration', label='Signature key configuration',
            values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
            default = 'jwks_uri'
            ) \
          .text('jwks_uri', label='JWKS URI', displayed_when="@[signature_key_configuration] = 'jwks_uri'") \
          .text('signature_key', label='Signature key', displayed_when="@[signature_key_configuration] = 'local_configuration'") \
        .end_section() \
        .start_section('client_params', title="Client Parameters", collapsible=True, collapsible_default=False) \
          .text('client_id', label='Client ID', clipboard_category='client_id') \
          .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
          .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
          .closed_list('response_type', label='Reponse type', 
            values={'code': 'code'},
            default = 'code'
            ) \
          .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
            values={'none': 'none', 'basic': 'client_secret_basic', 'form': 'client_secret_post'},
            default = 'basic'
            ) \
        .end_section() \
        .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=False) \
          .closed_list('display', label='Display', 
            values={'': '', 'page': 'page', 'popup': 'popup', 'touch': 'touch', 'wap': 'wap'},
            default = ''
            ) \
          .closed_list('prompt', label='Prompt', 
            values={'': '', 'none': 'none', 'login': 'login', 'consent': 'consent', 'select_account': 'select_account'},
            default = ''
            ) \
          .text('max_age', label='Max Age', clipboard_category='max_age') \
          .text('ui_locales', label='UI Locales', clipboard_category='ui_locales') \
          .text('id_token_hint', label='ID Token Hint', clipboard_category='id_token_hint') \
          .text('login_hint', label='Login Hint', clipboard_category='login_hint') \
          .text('acr_values', label='ACR Values', clipboard_category='acr_values') \
        .end_section() \
        .start_section('security_params', title="Security", collapsible=True, collapsible_default=False) \
          .text('state', label='State') \
          .text('nonce', label='Nonce') \
        .end_section() \
        .start_section('clientfedid_configuration', title="ClientFedID Configuration", collapsible=True, collapsible_default=True) \
          .text('token_endpoint_dns_override', label='Token endpoint DNS override', clipboard_category='token_endpoint_dns_override') \
          .text('userinfo_endpoint_dns_override', label='Userinfo endpoint DNS override', clipboard_category='userinfo_endpoint_dns_override') \
        .end_section() \

      form.set_request_parameters({
          'client_id': '@[client_id]',
          'redirect_uri': '@[redirect_uri]',
          'scope': '@[scope]',
          'response_type': '@[response_type]',
          'state': '@[state]',
          'nonce': '@[nonce]',
          'display': '@[display]',
          'prompt': '@[prompt]',
          'max_age': '@[max_age]',
          'ui_locales': '@[ui_locales]',
          'id_token_hint': '@[id_token_hint]',
          'login_hint': '@[login_hint]',
          'acr_values': '@[acr_values]',
        })
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
    Récupère les informations saisies dans /oidc/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oidc/client/preparerequest et placée dans le paramètre authentication_request
    
    Versions:
      26/02/2021 - 28/02/2021 (mpham) : version initiale
      09/12/2022 (mpham) ajout de token_endpoint_auth_method
      22/02/2023 (mpham) on retire les références à fetch_userinfo car l'appel à userinfo est maintenant manuel
      08/08/2024 (mpham) nouvelle organisation du contexte
      23/08/2024 (mpham) strip des données du formulaire
      27/02/2025 (mpham) les paramètres IdP n'étaient pas mis à jour au bon endroit
      08/06/2025 (mpham) DNS override for OIDC token and userinfo endpoints
    """
    
    self.log_info('Redirection to IdP requested')

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      oidc_idp_params = idp_params['oidc']
      for item in ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'userinfo_method', 'issuer', 'signature_key_configuration', 'jwks_uri', 'signature_key',
      'token_endpoint_dns_override', 'userinfo_endpoint_dns_override']:
        oidc_idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dansle contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['redirect_uri', 'client_id', 'scope', 'token_endpoint_auth_method', 'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values',
      'nonce']:
        app_params[item] = self.post_form.get(item, '').strip()
      
      # Récupération du secret
      if self.post_form.get('client_secret', '') == '':
        # on va récupérer le secret dans la configuration
        conf_idp = self.conf['idps'][self.context.idp_id]
        conf_app = conf_idp['oidc_clients'][self.context.app_id]
        app_params['client_secret'] = conf_app.get('client_secret!', '')
      else:
        app_params['client_secret'] = self.post_form.get('client_secret', '')

      if 'hr_verify_certificates' in self.post_form:
        idp_params['verify_certificates'] = 'on'
      else:
        idp_params['verify_certificates'] = 'off'

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
    """ Retour d'authentification depuis l'IdP
    
    Versions:
      14/09/2022 (mpham) version initiale
      22/12/2023 (mpham) utilisation de JWT pour la vérification de signature afin de pouvoir choisir la bibliothèque de validation
      05/08/2024 (mpham) adaptation aux pages continues
      09/08/2024 (mpham) nouvelle gestion du contexte
      04/09/2024 (mpham) récupération du jeton de raraichissement du jeton d'accès
      28/11/2024 (mpham) dans le contexte, on ajoute l'identifiant du client ayant récupéré les jetons
      23/12/2024 (mpham) les clés HMAC peuvent être données en JWK ou directement avec le secret
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
      08/06/2025 (mpham) DNS override for OIDC token and userinfo endpoints
    """

    self.add_javascript_include('/javascript/resultTable.js')
    self.add_javascript_include('/javascript/clipboard.js')
    try:
    
      self.log_info('Authentication callback')
      
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
      
      error = self.get_query_string_param('error')
      if error is not None:
        description = ''
        error_description = self.get_query_string_param('error_description')
        if error_description is not None:
          description = ', '+error_description
        raise AduneoError(self.log_error('IdP returned an error: '+error+description))
        
      # extraction des informations utiles de la session
      idp_id = self.context.idp_id
      app_id = self.context.app_id
      idp_params = self.context.idp_params
      oidc_idp_params = self.context.idp_params['oidc']
      app_params = self.context.last_app_params
      token_endpoint = oidc_idp_params['token_endpoint']
      client_id = app_params['client_id']
      redirect_uri = app_params['redirect_uri']

      self.add_html(f"<h3>OIDC callback from {html.escape(idp_params['name'])} for client {html.escape(app_params['name'])}</h3>")

      self.start_result_table()
      self.add_result_row('State returned by IdP', idp_state, 'idp_state')
      
      client_secret = app_params['client_secret']

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
      if token_endpoint_auth_method == 'basic':
        auth = (client_id, client_secret)
      elif token_endpoint_auth_method == 'form':
        data['client_secret'] = client_secret
      else:
        raise AduneoError('token endpoint authentication method '+token_endpoint_auth_method+' unknown. Should be basic or form')
      
      self.add_result_row('Token endpoint', token_endpoint, 'token_endpoint')
      self.end_result_table()
      self.add_html('<div class="intertable">Fetching token...</div>')
      self.log_info("Start fetching token")
      try:
        self.log_info("Connecting to "+token_endpoint)
        verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
        self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
        self.log_info(('  ' * 1)+'Client ID: '+client_id)
        
        token_endpoint_fqdn = urllib.parse.urlparse(token_endpoint).hostname
        dns_override = oidc_idp_params.get('token_endpoint_dns_override', '')
        if dns_override != '':
          self.log_info(('  ' * 1)+f"DNS override: {token_endpoint_fqdn} is revolved to {dns_override}")
        else:
          dns_override = None
        
        r = WebRequest.post(token_endpoint, form=data, basic_auth=auth, verify_certificate=verify_certificates, dns_override=dns_override)

      except Exception as error:
        self.add_html('<div class="intertable">Error : '+str(error)+'</div>')
        raise AduneoError(self.log_error(('  ' * 1)+'token retrieval error: '+str(error)))
      if r.status == 200:
        self.add_html('<div class="intertable">Success</div>')
      else:
        self.add_html('<div class="intertable">Error, status code '+str(r.status)+'</div>')
        raise AduneoError(self.log_error('token retrieval error: status code '+str(r.status)+", "+r.data))

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
      session_nonce = app_params['nonce']
      if session_nonce == '':
          self.log_info("No nonce was sent in the request")
      else:
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
      if 'issuer' not in oidc_idp_params:
        raise AduneoError("Issuer missing in authentication configuration", explanation_code='oidc_missing_issuer')
      if token_issuer == oidc_idp_params['issuer']:
        self.log_info("Token issuer verification OK: "+token_issuer)
        self.add_result_row('Issuer verification', 'OK: '+token_issuer, 'issuer_verification')
      else:
        self.log_error(('  ' * 1)+"Expiration verification failed:")
        self.log_error(('  ' * 2)+"Token issuer   : "+token_issuer)
        self.log_error(('  ' * 2)+"Metadata issuer: "+oidc_idp_params['issuer'])
        self.add_result_row('Issuer verification', "Failed\n  token issuer: "+token_issuer+"\n  metadata issuer:"+oidc_idp_params['issuer'], 'issuer_verification')
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
        self.add_result_row('Signature algorithm', f'Symmetric: {alg}', 'signature_algorithm')
        encoded_secret = base64.urlsafe_b64encode(str.encode(client_secret)).decode()
        key = {"alg":alg,"kty":"oct","use":"sig","kid":"1","k":encoded_secret}
        token_key = key

      else:
        # Signature asymétrique
        self.log_info('Asymmetric signature, fetching public key')
        self.add_result_row('Signature algorithm', f'Asymmetric: {alg}', 'signature_algorithm')
      
        # On regarde si on doit aller chercher les clés avec l'endpoint JWKS ou si la clé a été donnée localement
        if oidc_idp_params['signature_key_configuration'] == 'Local configuration':
          self.log_info('Signature JWK:')
          self.log_info(oidc_idp_params['signature_key'])
          token_jwk = json.loads(oidc_idp_params['signature_key'])
        else:
        
          # On extrait l'identifiant de la clé depuis l'id token
          idp_kid = token_header['kid']
          self.log_info('Signature key kid: '+idp_kid)
          self.add_result_row('Signature key kid', idp_kid, 'signature_key_kid')
          
          # on va chercher la liste des clés
          self.log_info("Starting IdP keys retrieval")
          self.add_result_row('JWKS endpoint', oidc_idp_params['jwks_uri'], 'jwks_endpoint')
          self.end_result_table()
          self.add_html('<div class="intertable">Fetching public keys...</div>')
          try:
            verify_certificates = Configuration.is_on(idp_params.get('verify_certificates', 'on'))
            self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_certificates else "disabled"))
            r = WebRequest.get(oidc_idp_params['jwks_uri'], verify_certificate=verify_certificates)
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
        jwt.is_signature_valid(token_key, raise_exception=True)
        self.log_info('Signature verification OK')
        if alg.startswith('HS'):
          self.add_result_row('Signature key', 'Client secret', copy_button=False)
        self.add_result_row('Signature verification', 'OK', copy_button=False)
      except Exception as error:
      
        default_case = True
        # Si on est en HS256, peut-être que le serveur a utilisé une clé autre que celle du client_secret (cas Keycloak)
        if alg.startswith('HS'):
          if oidc_idp_params['signature_key_configuration'] != 'local_configuration':
            self.log_info('HMAC signature (e.g HS256, HX512, etc.), client_secret not working. The server might have used another key. Put this key in configuration. Set Signature key configuration to Local configuration and enter the key in Signature key.')
          else:
            default_case = False
            self.log_info('HMAC signature (e.g HS256, HX512, etc.), client_secret not working, trying key from configuration')
            
            configuration_key = oidc_idp_params['signature_key']
            self.log_info('Configuration key:')
            self.log_info(configuration_key)
            
            if configuration_key.startswith('{"'):
              self.log_info(('  ' * 1)+"key seems to be in JWK format")
              token_key = json.loads({"alg":alg,"kty":"oct","use":"sig","kid":"1","k":configuration_key})
            else:
              self.log_info(('  ' * 1)+"key not in JWK format, converting key to:")
              token_key = {"alg":alg,"kty":"oct","use":"sig","kid":"1","k":configuration_key}
              self.log_info(('  ' * 2)+json.dumps(token_key))
          
            try:
              jwt.is_signature_valid(token_key, raise_exception=True)
              self.add_result_row('Signature key', 'Local configuration', copy_button=False)
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

      op_refresh_token = response.get('refresh_token')
      if op_refresh_token:
        # Jeton de rafraichissement du jeton d'accès pour authentification auprès de l'OP (userinfo en particulier)
        self.add_result_row('OP refresh token', op_refresh_token, 'op_refresh_token')
        self.log_info('OP refresh token: '+op_refresh_token)

      self.end_result_table()
      self.add_html('<h3>Authentication successful</h3>')
      
      # Enregistrement des jetons dans la session pour manipulation ultérieure
      #   Les jetons sont indexés par timestamp d'obtention
      token_name = 'Authn OIDC '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      token = {'name': token_name, 'type': 'id_token', 'app_id': app_id, 'id_token': id_token}
      if op_access_token:
        token['access_token'] = op_access_token
      if op_refresh_token:
        token['refresh_token'] = op_refresh_token
      self.context['id_tokens'][str(time.time())] = token

      # on considère qu'on est bien loggé
      self.logon('oidc_client_'+idp_id+'/'+app_id, id_token)
      
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
