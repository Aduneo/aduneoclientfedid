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

import html
import logging
import os
import traceback
import urllib.parse

from .BaseServer import BaseServer
from .BaseServer import AduneoError
from .BaseServer import WebRouter
from .Configuration import Configuration
from .CryptoTools import CryptoTools
from .Help import Help
from .WebConsole import WebConsole
# les imports suivants sont nécessaires pour la fonctionnalité de reconnaissance dynamique des redirect uri OIDC et OAuth 2
from .WebModules.OIDCClientLogin import OIDCClientLogin
from .WebModules.OIDCClientLogout import OIDCClientLogout
from .WebModules.OAuthClientLogin import OAuthClientLogin
from .WebModules.CASClientLogin import CASClientLogin
from .WebModules.CASClientLogout import CASClientLogout


# On vérifie que les prérequis pour SAML sont présents (sinon on désactive les fonctionnalités SAML)
#   Les modules lxml et xmlsec ne sont pas toujours faciles à installer
saml_prerequisite = False
try:
  import xmlsec
  saml_prerequisite = True
except:
  print("SAML disabled because xmlsec is not installed")
if saml_prerequisite:
  # l'import suivant est nécessaire pour la fonctionnalité de reconnaissance dynamique des URL ACS
  from .WebModules.SAMLClientLogin import SAMLClientLogin
  from .WebModules.SAMLClientLogout import SAMLClientLogout

# Chargement des modules web du dossier WebModules, pour que les décorateurs register_web_module et register_url soient appelés
current_module_name = __name__[:__name__.find('.')]
web_modules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'WebModules')
for filename in os.listdir(web_modules_dir):
  if not filename.startswith('__') and filename.endswith('.py'):
    module_name = filename[:-3]
    if module_name.casefold().startswith('saml'):
      if saml_prerequisite:
        exec("import "+current_module_name+".WebModules."+module_name)
    else:
      exec("import "+current_module_name+".WebModules."+module_name)


class Server(BaseServer):

  conf = Configuration.read_configuration('clientfedid.cnf')

  def __init__(self, request, client_address, server): 
    
    self.saml_prerequisite = saml_prerequisite
    
    self.row_number = 0  # pour l'affichage des tableaux de résultat
    super().__init__(request, client_address, server)


  def do_HEAD(self):
    return

    
  def do_GET(self):
    """
      Versions:
        09/08/2024 (mpham) version 2 du fichier de configuration
    """
  
    self.check_session()
    
    if self.path == '/favicon.ico':
      self.send_image('favicon.png')
    elif self.path.startswith('/images/') and self.path.endswith('.png'):
      self.send_static('images', self.path[8:])
    elif self.path.startswith('/css/') and self.path.endswith('.css'):
      self.send_static('css', self.path[5:])
    elif self.path.startswith('/javascript/') and self.path.endswith('.js'):
      self.send_static('javascript', self.path[12:])
    elif self.path.startswith('/html/') and self.path.endswith('.html'):
      self.send_static('html', self.path[6:])
    else:
  
      url_items = urllib.parse.urlparse(self.path)

      method_name = 'get' + url_items.path.replace('/', '_')

      if (method_name in dir(self)):
        eval('self.'+method_name+'()')
      elif WebRouter.is_authorized_url(url_items.path, 'GET'):
        web_router = WebRouter(url_items.path, 'GET')
        try:
          web_router.serve_url(self)
        except AduneoError as error:
          self.send_page(str(error), clear_buffer=True)
      else:
        # Regarder s'il ne s'agit pas d'un chemin défini comme redirect_uri OIDC dans la configuration
        callback_found = self._search_callback_in_configuration()
        
        if not callback_found:
          # Regarder s'il ne s'agit pas d'un chemin défini comme redirect_uri OIDC dans la page de login
          callback_found = self._search_callback_in_session()
        
        if not callback_found:
          self.send_page('404 !', code=404)

    
  def do_POST(self):
  
    # On ne crée pas la session si elle n'existe pas à cause du problème SameSite SAML
    #   De toute façon si on accède à l'application par un premier POST, ce n'est pas normal
    self.check_session(create_session=False)
    self.parse_post()
  
    url_items = urllib.parse.urlparse(self.path)
    method_name = 'post' + url_items.path.replace('/', '_')
    
    if (method_name in dir(self)):
      eval('self.'+method_name+'()')
    elif WebRouter.is_authorized_url(url_items.path, 'POST'):
      web_router = WebRouter(url_items.path, 'POST')
      try:
        web_router.serve_url(self)
      except AduneoError as error:
        self.send_page(str(error), clear_buffer=True)
    else:
      # Regarder s'il ne s'agit pas d'un chemin défini comme redirect_uri OIDC dans la configuration
      callback_found = self._search_callback_in_configuration()
      
      if not callback_found:
        # Regarder s'il ne s'agit pas d'un chemin défini comme redirect_uri OIDC dans la page de login
        params = urllib.parse.parse_qs(url_items.query)
        if 'state' in params:
          # on a un state, on regarde si on trouve un redirect_uri dans la requête en question
          #request = self.get_session_value(state)
          # TODO : continuer !
          #print(request)
          pass
      
      if not callback_found:
        self.send_page('404 !', code=404)

    
  def do_PUT(self):
  
    self.check_session(create_session=False)
    self.parse_post()
  
    url_items = urllib.parse.urlparse(self.path)
    method_name = 'put' + url_items.path.replace('/', '_')
    
    if (method_name in dir(self)):
      eval('self.'+method_name+'()')
    else:
      self.send_page('404 !', code=404)


  def _search_callback_in_configuration(self):
    """ Regarde si l'URL n'est pas référencée dans la configuration
      
      Permet de donner n'importe quelle URL pour redirect_uri ou sp_acs_url
        Appelle la méthode correspondante (retour d'authentification ou de déconnexion) en fonction du contexte
    
      Returns:
        True si l'URL a bien été trouvée et la requête traitée
    
      Versions:
        09/08/2024 (mpham) version initiale copiée de do_GET
        02/02/2025 (mpham) CAS
    """

    callback_found = False
    
    url_items = urllib.parse.urlparse(self.path)
    for idp in Server.conf['idps'].values():
      
      if not callback_found and idp.get('oidc_clients'):
        for client in idp['oidc_clients'].values():
          if 'redirect_uri' in client:
            conf_url = urllib.parse.urlparse(client['redirect_uri'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_oidc_login_callback()
              break
              
          if 'post_logout_redirect_uri' in client:
            conf_url = urllib.parse.urlparse(client['post_logout_redirect_uri'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_oidc_logout_callback()
              break

      if not callback_found and idp.get('oauth2_clients'):
        for client in idp['oauth2_clients'].values():
          if 'redirect_uri' in client:
            conf_url = urllib.parse.urlparse(client['redirect_uri'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_oauth_login_callback()
              break
              
      if not callback_found and idp.get('saml_clients'):
        for client in idp['saml_clients'].values():
          if 'sp_acs_url' in client:
            conf_url = urllib.parse.urlparse(client['sp_acs_url'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_saml_acs()
              break
          if 'sp_slo_url' in client:
            conf_url = urllib.parse.urlparse(client['sp_slo_url'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_saml_slo()
              break

      if not callback_found and idp.get('cas_clients'):
        for client in idp['cas_clients'].values():
          if 'service_url' in client:
            conf_url = urllib.parse.urlparse(client['service_url'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_cas_login_callback()
              break
          if 'logout_service_url' in client:
            conf_url = urllib.parse.urlparse(client['logout_service_url'])
            if url_items.path == conf_url.path:
              # Bingo
              callback_found = True
              self._client_cas_logout_callback()
              break

    return callback_found
    
    
  def _search_callback_in_session(self):
    """ Regarde si l'URL n'est pas référencée dans la session, parmi les paramètres modifiés par l'utilisateur lors d'une authentification
      
      Permet de donner n'importe quelle URL pour redirect_uri ou sp_acs_url
        Appelle la méthode correspondante (retour d'authentification ou de déconnexion) en fonction du contexte
    
      Returns:
        True si l'URL a bien été trouvée et la requête traitée
    
      Versions:
        02/02/2025 (mpham) version initiale
    """

    callback_found = False

    url_items = urllib.parse.urlparse(self.path)
    params = urllib.parse.parse_qs(url_items.query)
    if 'state' in params:
      # on a un state, on regarde si on trouve un redirect_uri dans la requête en question
      state = params['state'][0]
      
      go_on = True

      context_id = self.get_session_value(state)
      if go_on and context_id:
        context = self.get_session_value(context_id)
      else:
        go_on = False
      
      if go_on and context:
        app_params = context.last_app_params
      else:
        go_on = False

      if go_on and app_params:
        redirect_uri = app_params.get('redirect_uri')
        if redirect_uri:
          session_url = urllib.parse.urlparse(redirect_uri)
          if session_url.path == url_items.path:
            if context['flow_type'] == 'OIDC':
              callback_found = True
              self._client_oidc_login_callback()
            elif context['flow_type'] == 'OAuth2':
              callback_found = True
              self._client_oauth_login_callback()
          
        if not callback_found:
          post_logout_redirect_uri = app_params.get('post_logout_redirect_uri')
          if post_logout_redirect_uri:
            session_url = urllib.parse.urlparse(post_logout_redirect_uri)
            if session_url.path == url_items.path:
              if context['flow_type'] == 'OIDC':
                callback_found = True
                self._client_oidc_logout_callback()
          
        if not callback_found:
          sp_acs_slo = app_params.get('sp_acs_url')
          if sp_acs_url:
            session_url = urllib.parse.urlparse(sp_acs_url)
            if session_url.path == url_items.path:
              if context['flow_type'] == 'SAML':
                callback_found = True
                self._client_saml_acs()
      
        if not callback_found:
          sp_acs_url = app_params.get('sp_slo_url')
          if sp_slo_url:
            session_url = urllib.parse.urlparse(sp_slo_url)
            if session_url.path == url_items.path:
              if context['flow_type'] == 'SAML':
                callback_found = True
                self._client_saml_slo()
      
      if not callback_found:
        # les sessions CAS sont différentes (pas de state)
        context = self.get_session_value('last_cas_context')
        if context:
          app_params = context.last_app_params
          service_url = app_params.get('service_url')
          if service_url:
            session_url = urllib.parse.urlparse(service_url)
            if session_url.path == url_items.path:
              if context['flow_type'] == 'CAS':
                callback_found = True
                self._client_cas_login_callback()
      
        if not callback_found:
          logout_service_url = app_params.get('logout_service_url')
          if logout_service_url:
            session_url = urllib.parse.urlparse(logout_service_url)
            if session_url.path == url_items.path:
              if context['flow_type'] == 'CAS':
                callback_found = True
                self._client_cas_logout_callback()

    return callback_found
    
    
  def get_OBS_obsolete(self):

    """
    homepage
    
    mpham 27/01/2021 - 28/02/2021
    """
  
    self.add_content("""
      <script>
      function authOIDC(spId) {
        location.href = '/client/oidc/login/preparerequest?id='+oidcId
      }
      function removeOIDC(rpId, name) {
        if (confirm("Remove OIDC client "+name+'?')) {
          location.href = '/client/oidc/admin/removeclient?id='+rpId;
        }
      }
      function authSAML(spId) {
        location.href = '/client/saml/login/preparerequest?id='+oidcId
      }
      function removeSAML(spId, name) {
        if (confirm("Remove SAML SP "+name+'?')) {
          location.href = '/client/saml/admin/removeclient?id='+spId;
        }
      }

      function authOAUTH(spId) {
        location.href = '/client/oauth/login/preparerequest?id='+oidcId
      }
      function removeOAUTH(spId, name) {
        if (confirm("Remove OAuth SP "+name+'?')) {
          location.href = '/client/oauth/admin/removeclient?id='+spId;
        }
      }

      function displayPadding(boolean) {
        padder = document.getElementById('padder');
        if (boolean == 1) {
          padder.style.display = "block";
        }
        if (boolean == 0) {
          padder.style.display = "none";
        }
      }
      
      //function openConsole() {
      //  window.open("/webconsole", "console", "directories=no,titlebar=no,toolbar=no,location=no,status=no,menubar=no,scrollbars=no,resizable=no,height=500, width=500");
      //}
      </script>

      <ul class="mainMenu">
        <!-- <li onmouseover="displayPadding(1)" onmouseout="displayPadding(0)"> -->
        <li>
          <span><a href="/client/oidc/admin/modifyclient" class="button">Add OIDC Client</a></span>
          <!--
          <ul>
            <li><a href="/client/oidc/admin/modifyclient" class="button">Configuration</a></li>
            <li><a href="/client/oidc/admin/modifyclient/guide" class="button">Guide</a></li>
          </ul>
          -->
        </li>
      </ul>""")
    self.add_content("""
      <span><a href="/client/oauth/admin/modifyclient" class="button">Add OAuth Client</a></span>
    """)
    if self.saml_prerequisite:
      self.add_content("""
        <span><a href="/client/saml/admin/modifyclient" class="button">Add SAML SP</a></span>""")
    self.add_content("""
      <div id="padder" style="margin-top: 9%; display: none;"></div>
      <div>
        <h2 class="idp_list">OpenID Connect Clients (Relaying Parties)</h2>
    """)
    
    for rp_id in Server.conf['oidc_clients']:
      rp = Server.conf['oidc_clients'][rp_id]
      self.add_content('<div class="idpList">')
      self.add_content('<span style="cursor: pointer; min-height: 100%; display: inline-flex; align-items: center;" onclick="authOIDC(\''+html.escape(rp_id)+'\')">'+html.escape(rp['name'])+'</span>')
      self.add_content('<span>')
      if (self.is_logged('oidc_client_'+rp_id)):
        self.add_content('<span style="heigth: 100%; display: inline-block; vertical-align: middle;"><img src="/images/logged.png" /></span>')
      self.add_content('<span><a href="/client/oidc/login/preparerequest?id='+html.escape(rp_id)+'" class="middlebutton">Login</a></span>')
      self.add_content('<span><a href="/client/oidc/logout/preparerequest?id='+html.escape(rp_id)+'" class="middlebutton">Logout</a></span>')
      self.add_content('<span><a href="/client/oidc/admin/modifyclient?id='+html.escape(rp_id)+'" class="middlebutton">Config</a></span>')
      self.add_content('<span class="middlebutton" onclick="removeOIDC(\''+html.escape(rp_id)+'\', \''+rp['name']+'\')">Remove</span>')
      self.add_content('</span>')
      self.add_content('</div>')

    if self.saml_prerequisite:
      self.add_content('<h2>SAML Service Providers</h2>')
      for sp_id in Server.conf['saml_clients']:
        sp = Server.conf['saml_clients'][sp_id]
        self.add_content('<div class="idpList">')
        self.add_content('<span style="cursor: pointer; min-height: 100%; display: inline-flex; align-items: center;" onclick="authSAML(\''+html.escape(sp_id)+'\')">'+html.escape(sp['name'])+'</span>')
        self.add_content('<span>')
        if (self.is_logged('saml_client_'+sp_id)):
          self.add_content('<span style="heigth: 100%; display: inline-block; vertical-align: middle;"><img src="/images/logged.png" /></span>')
        self.add_content('<span><a href="/client/saml/login/preparerequest?id='+html.escape(sp_id)+'" class="middlebutton">Login</a></span>')
        self.add_content('<span><a href="/client/saml/logout/preparerequest?id='+html.escape(sp_id)+'" class="middlebutton">Logout</a></span>')
        self.add_content('<span><a href="/client/saml/admin/modifyclient?id='+html.escape(sp_id)+'" class="middlebutton">Config</a></span>')
        self.add_content('<span class="middlebutton" onclick="removeSAML(\''+html.escape(sp_id)+'\', \''+sp['name']+'\')">Remove</span>')
        self.add_content('</span>')
        self.add_content('</div>')

    self.add_content('<h2>OAuth Clients</h2>')
    for sp_id in Server.conf['oauth_clients']:
      sp = Server.conf['oauth_clients'][sp_id]
      self.add_content('<div class="idpList">')
      self.add_content('<span style="cursor: pointer; min-height: 100%; display: inline-flex; align-items: center;" onclick="authSAML(\''+html.escape(sp_id)+'\')">'+html.escape(sp['name'])+'</span>')
      self.add_content('<span>')
      if (self.is_logged('oauth_client_'+sp_id)):
        self.add_content('<span style="heigth: 100%; display: inline-block; vertical-align: middle;"><img src="/images/logged.png" /></span>')
      self.add_content('<span><a href="/client/oauth/login/preparerequest?id='+html.escape(sp_id)+'" class="middlebutton">Login</a></span>')
      self.add_content('<span><a href="/client/oauth/logout/preparerequest?id='+html.escape(sp_id)+'" class="middlebutton">Revoke AT</a></span>')
      self.add_content('<span><a href="/client/oauth/admin/modifyclient?id='+html.escape(sp_id)+'" class="middlebutton">Config</a></span>')
      self.add_content('<span class="middlebutton" onclick="removeOAUTH(\''+html.escape(sp_id)+'\', \''+sp['name']+'\')">Remove</span>')
      self.add_content('</span>')
      self.add_content('</div>')

    self.add_content('</div>')
    
    self.send_page()


  def get_help(self):
  
    """
    Retourne les rubriques d'aide sous forme de JSON
      "header": "..."
      "content" : "...'
      
    mpham 13/04/2021
    """
    
    help_handler = Help(self)

    try:
      help_handler.send_help()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def post_help(self):
  
    """
    Enregistre une rubrique d'aide
      
    mpham 22/02/2024
    """
    
    help_handler = Help(self)

    try:
      help_handler.save_help()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def get_oidc_client_preparerequestazerty(self):

    """
    Prépare la requête d'authentification OIDC
      
    mpham 05/03/2021
    """

    oidc_client_login = OIDCClientLogin(self)
    
    try:
      oidc_client_login.prepare_request()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def post_oidc_client_sendrequestazerty(self):

    """
    Récupère les informations saisies dans /oidc/client/preparerequest pour les mettre dans la session
      (avec le state comme clé)
    Redirige vers l'IdP grâce à la requête générée dans /oidc/client/preparerequest et placée dans le paramètre authentication_request
      
    mpham 05/03/2021
    """

    oidc_client_login = OIDCClientLogin(self)
    
    try:
      oidc_client_login.send_request()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_oidc_login_callback(self):

    """
    Retour d'authentification
    
    mpham 05/03/2021
    """

    oidc_client_login = OIDCClientLogin(self)
    
    try:
      oidc_client_login.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_oauth_login_callback(self):

    """
    Retour d'authentification
    
    mpham 19/01/2023
    """

    oauth_client_login = OAuthClientLogin(self)
    
    try:
      oauth_client_login.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_oidc_logout_callback(self):

    oidc_logout = OIDCClientLogout(self)

    try:
      oidc_logout.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def get_oidc_client_modifyclient_guide(self):

    oidc_client_admin = OIDCClientAdminGuide(self)

    try:
      oidc_client_admin.display()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def post_oidc_client_modifyclient_guide(self):

    oidc_client_admin = OIDCClientAdminGuide(self)

    try:
      oidc_client_admin.modify()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)
    

  def _client_saml_acs(self):

    """
      réceptionne la réponse SAML
      
      mpham 02/03/2021
    """
    
    saml_client_login = SAMLClientLogin(self)
    
    try:
      saml_client_login.authcallback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_saml_slo(self):

    saml_logout = SAMLClientLogout(self)

    try:
      saml_logout.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_cas_login_callback(self):

    cas_login = CASClientLogin(self)

    try:
      cas_login.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def _client_cas_logout_callback(self):

    cas_logout = CASClientLogout(self)

    try:
      cas_logout.callback()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def check_saml_certificate_exists(self) -> str:
    """ Vérifie que le certificat SAML par défaut existe
    
    DEPLACE VERS SAMLCLIENTADMIN
    
    dans les fichiers
    - conf/aduneo_saml.key pour la clé privée
    - conf/aduneo_saml.crt pour le certificat
    
    Le crée sinon.
    
    Returns:
      Certificate file path
    
    mpham 21/01/2023
    """
    
    key_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.key')
    crt_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.crt')
    
    if not os.path.isfile(key_file_path) or not os.path.isfile(crt_file_path):
      logging.info("Default SAML certificate does not exist, a key and certificate are generated")

      CryptoTools.generate_self_signed_certificate('https://www.aduneo.com', key_file_path, crt_file_path)
      
    return crt_file_path


  def get_downloadservercertificate(self):
    
    """
    Retourne le certificat du serveur (utilisé pour SAML)

    DEPLACE VERS SAMLCLIENTADMIN
    
    Le crée s'il n'existe pas
    
    mpham 21/01/2023
    """

    try:
      crt_file_path = self.check_saml_certificate_exists()
    except:
      send_page('Certificate not configured', code=400, clear_buffer=True)
      return
    
    download_filename = os.path.basename(crt_file_path)

    self.send_response(200)
    self.send_header('Content-type', 'application/x-pem-file')
    self.send_header('Content-disposition', 'filename='+download_filename)
    self.end_headers()
    
    in_file = open(crt_file_path, 'rb')
    chunk = in_file.read(1024)
    while chunk:
      self.wfile.write(chunk)
      chunk = in_file.read(1024)
    in_file.close()


  def get_generatecertificate(self):
  
    """
    Génère un biclé, un certificat autosigné avec la clé publique et retourne clé privée et certificat en format PEM
    """
  
    try:
      (private_key, certificate) = CryptoTools.generate_key_self_signed()
      json_result = {"private_key": private_key, "certificate": certificate}
      self.send_json(json_result)
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)
    
    
  def get_tpl(self):  
    self.send_template('test.html', titre='Ceci est un titre', nom='Jean Moulin')


  def get_webconsole(self):

    webconsole = WebConsole(self)

    try:
      webconsole.display()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)

  def get_webconsole_buffer(self):

    webconsole = WebConsole(self)

    try:
      webconsole.send_buffer()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)


  def put_webconsole_buffer(self):

    webconsole = WebConsole(self)

    try:
      webconsole.clear_buffer()
    except AduneoError as error:
      self.send_page(str(error), clear_buffer=True)

