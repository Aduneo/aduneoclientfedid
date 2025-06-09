# -*- coding: utf-8 -*-
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

import html
import http.cookies
import importlib
import json
import os
import urllib.parse
import uuid
import logging

from http.server import BaseHTTPRequestHandler


class BaseServer(BaseHTTPRequestHandler):

  sessions = {}  # TODO faire expirer les sessions pour libérer de la mémoire

  def __init__(self, request, client_address, server): 
    """
    le membre sessionid contient l'identifiant de session
    il est généré dans set_session_value() (s'il n'existe pas déjà)

    Attention, ne rien mettre après super(), car ce ne sera exécuté qu'après le traitement de la page
    
    mpham 27/01/2021
    26/12/2022 (mpham) : POST JSON
    24/03/2023 (mpham) : gestion des pages continues (continuous pages)
    """
    
    self.top_sent = False
    self.content = ''
    self.session_id = None

    self.continuous_page = False
    self.continuous_page_id = None

    self.post_form = None
    self.post_json = None
    super().__init__(request, client_address, server)
    
   
  def log_message(self, format, *args):
    """Surcharge des logs du serveur pour les envoyer dans les logs de l'application/json
    
    et par la même occasion filtre les requêtes de la console web des journaux
    
    27/05/2022 (mpham) : version initiale
    03/08/2023 (mpham) : on ne logge pas /continuouspage/poll
    """
    
    if not args[0].startswith("GET /webconsole/buffer") and not args[0].startswith("GET /continuouspage/poll"):
      logging.info(" HTTP %s " % self.address_string()+format%args)


  def parse_post(self):
    """
    26/12/2022 (mpham) : POST JSON
    """

    content_length = int(self.headers['Content-Length'])
    post_data = self.rfile.read(content_length).decode('utf-8')
    
    if self.headers['Content-Type'] == 'application/json':
    
      self.post_json = json.loads(post_data)
    
    else:
    
      self.post_form = {}
      for item in post_data.split('&'):
        equalsPos = item.find('=')
        if equalsPos == -1:
          self.post_form[item] = ''
        else:
          key = urllib.parse.unquote_plus(item[:equalsPos])
          self.post_form[key] = urllib.parse.unquote_plus(item[equalsPos+1:])
        

  def add_content(self, content):

    if self.top_sent:
      page = bytes(content, "UTF-8")
      self.wfile.write(page)
    else:
      self.content += content

   
  def send_page(self, content = '', code=200, clear_buffer=False):
    
    """
    envoie une page au navigateur

    Versions:
      27/01/2021 - 24/02/2021 (mpham) version intiale
      30/03/2023 (mpham) prise en compte des pages continues
      10/01/2025 (mpham) les templates sont pris en charge par @register_page_url, on n'envoie plus de templates pour les pages non continues
    """
    
    if clear_buffer:
      self.content = ''

    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.add_content(self.continuous_page_id, html=self.content+content, stop=True)
    else:
      page = bytes(self.content + content, "UTF-8")
      self.wfile.write(page)


  def send_page_raw(self, content = '', code=200, clear_buffer=False):
    if clear_buffer:
      self.content = ''

    self.send_page_top(code, template=False)
    page = bytes(self.content + content, "UTF-8")
    self.wfile.write(page)  
    

  def send_page_top(self, code=200, template=True, send_cookie=True):
    
    """
    envoie le haut d'une page
    
    24/02/2021 (mpham) version initiale
    """
    
    self.send_response(code)
    self._send_page_headers(send_cookie)
    
    open_webconsole = False
    if (self.conf):
      from .Configuration import Configuration
      open_webconsole = Configuration.is_parameter_on(self.conf, '/preferences/open_webconsole', default=False)
    
    if (template):
      header = "<html><head><title>Aduneo - ClientFedID</title>"
      header += '<link rel="stylesheet" href="/css/aduneo.css">'
      header += '</head>'
      header += '<script>var autoOpenWebconsole = '+('true' if open_webconsole else 'false')+';</script>'
      header += '<script src="/javascript/common.js"></script>'
      header += '<body><div style="color: #FFA500; font-family: Tahoma; font-size: 40px; background-color: #004c97; height: 74px;"><a href="https://www.aduneo.com"><img style="width: 294px; height: 64px; vertical-align: middle; margin-left: 8px; margin-top: 5px;" src="/images/aduneo.png"></a><span style="margin-left: 30px; vertical-align: middle;">ClientFedID - Identity Federation Test Client</span>'
      header += '<a href="/"><img style="height: 36px; float: right; margin-top: 20px; margin-right: 20px" src="/images/home.png"></a>'
      header += '<span><a class="button" onclick="openConsole(true);" style="float: right;margin-top: 15;margin-right: 10;">Logs</a></span></div>'
      header += '<div style="margin-top: 20px; margin-left: 50px; font-family: Verdana;">'
      page = bytes(header, "UTF-8")
      self.wfile.write(page)
    
    self.top_sent = True
    

  def send_page_bottom(self):
    
    """
    envoie le bas d'une page au navigateur
    
    mpham 24/02/2021
    """
    
    footer = '</div>'
    footer += "</body></html>"
    page = bytes(footer, "UTF-8")
    self.wfile.write(page)


  def add_html(self, html):
    """ Envoie au navigateur du code HTML
    
    Args:
      html: HTML à envoyer
      
    Versions:
      29/03/2023 (mpham) version initiale
    """
    
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.add_content(self.continuous_page_id, html=html)
    else:
      self.add_content(html)
      

  def add_javascript(self, code):
    """ Envoie au navigateur du code Javascript à exécuter
    
    Utile en page continue, car <script> ne fonctionne pas avec add_content
    
    Args:
      code: code Javascript à exécuter
      
    Versions:
      30/03/2023 (mpham) version initiale
    """
    
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.add_content(self.continuous_page_id, javascript=code)
    else:
      self.add_content('<script>{code}</script>'.format(code=code))


  def add_javascript_include(self, url):
    """ Envoie au navigateur un include de fichier Javascript
    
    Utile en page continue, car <script> ne fonctionne pas avec add_content
    
    Args:
      url: URL de la ressource Javascript
      
    Versions:
      29/03/2023 (mpham) version initiale
    """
    
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.add_content(self.continuous_page_id, javascript_include=url)
    else:
      self.add_content('<script src="{url}"></script>'.format(url=url))
      

  def start_continuous_page_block(self):
    """ Démarrage un bloc de contenu insécable
    
    Le bloc doit être envoyé dans son ensemble, sinon le navigateur va ajouter des éléments parasites.
    
    C'est par exemple le cas si on récupère du tampon un tableau (table) en plusieurs fois.
    A chaque récupération, le navigateur ferme le tableau.
    
    Versions:
        05/08/2024 (mpham) version initiale
    """
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.start_continuous_page_block(self.continuous_page_id)


  def end_continuous_page_block(self):
    """ Ferme un bloc de contenu insécable
    
    Versions:
      05/08/2024 (mpham) version initiale
    """
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.end_continuous_page_block(self.continuous_page_id)


  def send_redirection(self, url:str):
    """ Redirige le navigateur vers une autre page
    
    Versions:
      27/01/2021 (mpham) version initiale
      28/02/2025 (mpham) compatibilité avec les pages continues (pour le formulaire OAuth 2 qui se conclut par un 302 (code) ou par une continuation (client credentials)
    """
  
    if self.continuous_page:
      from .WebModules.ContinuousPage import ContinuousPageBuffer
      ContinuousPageBuffer.redirect(self.continuous_page_id, url)
    else:
      self.send_response(302)
      self.send_header('location', url)
      if self.session_id is not None:
        self.send_header('Set-Cookie', 'fedclient_sessionid='+self.session_id+'; HttpOnly')
      self.end_headers()
    

  def send_json_page(self, html:str='', javascript:str=''):
    
    """
    Envoie du contenu à la SPA interne, qui l'attend get getHtmlJson
    (voir le fichier requestSender.js)
    
    Si self.content n'est pas vide, on l'ajoute avant au HTML
    
    Args:
      html: code HTML
      javascript : code Javascript
    
    Version
      23/12/2022 (mpham) : version initiale
    """
    
    html = self.content + html
    self.send_json({'html': html, 'javascript': javascript})
    
    
  def send_json(self, dictionnary: dict):
    
    """
    Retourne un objet JSON
    
    mpham 13/04/2021
    """
    
    self.send_response(200)
    self.send_header('Content-type', 'application/json')
    self.end_headers()

    content = bytes(json.dumps(dictionnary), "UTF-8")
    self.wfile.write(content)
      
      
  def send_image(self, path):
    
    """
    Les images sont nécessairement des PNG dans le dossier /static/images
    
    mpham 28/01/2021 - 12/02/2021 - 04/03/2021
    """

    self.send_static('images', path)


  def send_css(self, path):
    
    """
    Les styles sont nécessairement dans le dossier /static/css et se terminent par .css
    
    mpham 12/02/2021 - 04/03/2021
    """

    self.send_static('css', path)

  
  def send_javascript(self, path):
    
    """
    Les styles sont nécessairement dans le dossier /static/css et se terminent par .css
    
    mpham 12/02/2021 - 04/03/2021
    """

    self.send_static('javascript', path)

  
  def send_static(self, static_type: str, path: str):
    
    """
    Retourne un fichier static, placé dans le sous-dossier static_type du dossier static
    Vérifie que le fichier se trouve bien dans le dossier en question et que le chemin ne contient pas des ..
    
    mpham 12/02/2021 - 04/03/2021
    """
    
    content_type_map = {'images': 'image/png', 'css': 'text/css', 'javascript': 'text/javascript', 'html': 'text/html'}
    extension_map = {'images': '.png', 'css': '.css', 'javascript': '.js', 'html': '.html'}
    
    css_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static', static_type)
    requested_path = os.path.join(css_dir, path)

    if not BaseServer.check_path_traversal(css_dir, requested_path):
      self.send_page('404 !', code=404, clear_buffer=True)
    elif not path.endswith(extension_map[static_type]):
      self.send_page('404 !', code=404, clear_buffer=True)
    else:
    
      self.send_response(200)
      self.send_header('Content-type', content_type_map[static_type])
      #self.send_header('Cache-Control', 'public, max-age=3600')
      self.send_header('Cache-Control', 'no-cache')
      self.end_headers()
      
      in_file = open(requested_path, 'rb')
      chunk = in_file.read(1024)
      while chunk:
        self.wfile.write(chunk)
        chunk = in_file.read(1024)
      in_file.close()


  def download_file(self, path:str, content_type:str='application/octet-stream', filename:str=None):
    """ Télécharge un fichier
    
    Args:
      path: chemin sur le serveur ClientFedID, qui doit être dans le dossier de configuration
      content_type: sans commentaire
      filename: prend par défaut le nom du fichier sur le disque
      
    Versions:
      01/01/2025 (mpham) version initiale
    """
    
    from .Configuration import Configuration
    if not BaseServer.check_path_traversal(Configuration.conf_dir, path):
      self.send_page('404 !', code=404, clear_buffer=True)

    if not filename:
      filename = os.path.basename(path)

    self.send_response(200)
    self.send_header('Content-type', content_type)
    self.send_header('Content-disposition', 'filename='+filename)
    self.end_headers()
    
    in_file = open(path, 'rb')
    chunk = in_file.read(1024)
    while chunk:
      self.wfile.write(chunk)
      chunk = in_file.read(1024)
    in_file.close()
    

  def send_template(self, template_name:str, **parameters):
    """
    Mécanisme de template simplifié
    Fourniture du template par un nom de fichier dans le dossier templates
    
    16/08/2021 (mpham) version initiale
    """
  
    tpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    requested_path = os.path.join(tpl_dir, template_name)

    if not BaseServer.check_path_traversal(tpl_dir, requested_path):
      self.send_page('404 !', code=404, clear_buffer=True)
    else:
      with open(requested_path, mode='r', encoding="utf-8") as in_file:
        template_content = in_file.read()
        
      self.send_page(self.apply_template(template_content, **parameters))
      

  def send_template_raw(self, template_name:str, **parameters):
  
    """
    Mécanisme de template simplifié
    Fourniture du template par un nom de fichier dans le dossier templates
    
    mpham 16/08/2021
    """
  
    tpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    requested_path = os.path.join(tpl_dir, template_name)

    if not BaseServer.check_path_traversal(tpl_dir, requested_path):
      self.send_page('404 !', code=404, clear_buffer=True)
    else:
      with open(requested_path, mode='r', encoding="utf-8") as in_file:
        template_content = in_file.read()
        
      self.send_page_raw(self.apply_template(template_content, **parameters))
      

  def _send_page_headers(self, send_cookie:bool=True):
    """ Envoie les en-têtes d'une page :
        - le Content-Type
        - le cookie de session
        
    Args:
      send_cookie: pour indiquer s'il faut envoyer le cookie de session
        
    Versions:
      29/03/2023 (mpham) version initiale transférée de send_page_top
    """

    self.send_header('Content-type', 'text/html; charset=utf-8')
    if send_cookie and self.session_id is not None:
      self.send_header('Set-Cookie', 'fedclient_sessionid='+self.session_id+'; Max-Age=1200; HttpOnly; path=/;')
    self.end_headers()


  def apply_template(self, template:str, **parameters):
  
    """
    Mécanisme de template simplifié
    Fourniture du template directement en chaîne
    
    mpham 16/08/2021
    """
    
    from .Template import Template
  
    return Template.apply_template(template, **parameters)

  
  def check_session(self, create_session=True):
  
    """
    Génère un identifiant de session s'il n'en existe pas déjà dans les cookies
    
    On appelle cette méthode en initialisation de GET et POST pour s'assurer qu'on envoie bien l'id de session
      dans les en-têtes
      
    On a eu en effet le cas où
    - on appelle send_page_top() avant d'avoir besoin de session
    - puis on ajoute une information dans la session qui n'existe pas
    - on génère donc un identifiant, mais comme les en-têtes ont déjà été envoyés, c'est trop tard
    
    mpham 01/03/2021
    """
    
    session_exists = False
    if self.headers.get('Cookie') is not None:
      cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
      if 'fedclient_sessionid' in cookies:
        self.session_id = cookies['fedclient_sessionid'].value
        session_exists = True
        
    if not session_exists and create_session:
      self.session_id = str(uuid.uuid4())

  
  def set_session_value(self, key, value):
    
    """
    met une variable en session
    
    mpham 27/01/2021
    """
    
    if self.sessions.get(self.session_id) is None:
      self.sessions[self.session_id] = {}
      
    self.sessions[self.session_id][key] = value
    
    
  def get_session_value(self, key):
    
    """
    récupère une variable de la session
    retourne None si elle n'existe pas
    
    mpham 27/01/2021
    """
    
    value = None
    
    if self.sessions.get(self.session_id) is not None:
      value = self.sessions[self.session_id].get(key)
      
    return value

    
  def del_session_value(self, key):
    
    """
    Supprime une variable de la session
    retourne None si elle n'existe pas
    
    mpham 01/03/2021
    """

    if self.session_id is not None:
      self.sessions[self.session_id].pop(key, None)
      

  def logon(self, idp_id, id_token = 'authenticated'):
    
    """
    Démarre une session authentifiée par un IdP
    
    mpham 01/03/2021
    """
    
    self.set_session_value('session_'+idp_id, id_token)
    
    
  def logoff(self, idp_id):
    
    """
    Met un terme à une session authentifiée par un IdP
    
    mpham 01/03/2021
    """
    
    self.del_session_value('session_'+idp_id)    
    
    
  def is_logged(self, idp_id):
    
    """
    Indique si une session est en cours avec une authentifiction par un IdP
    
    mpham 01/03/2021
    """
    
    return self.get_session_value('session_'+idp_id) is not None

    
  def check_path_traversal(base_dir, requested_path):

    """
    vérifie que le chemin demandé par le client ne fait pas de directory traversal
    retourne True si le chemin est conforme, False en cas d'attaque
    
    mpham 12/02/2021
    """
    
    return os.path.commonprefix((os.path.realpath(requested_path).lower(), base_dir.lower())) == base_dir.lower()
    
    
class BaseHandler:
  
  def __init__(self, hreq):
    
    """
    hreq est l'instance courante de HTTPRequestHandler
    
    Versions:
      01/03/2021 (mpham) version initiale
      26/01/2025 (mpham) remontée des en-têtes
    """
    
    from .Server import Server  # pour éviter les imports circulaires
    self.conf = Server.conf
    self.post_form = hreq.post_form
    self.post_json = hreq.post_json
    self.hreq = hreq
    self.server = hreq.server
    self.headers = hreq.headers
    
    self.result_in_table = False   # Indique si une table est ouverte (voir start_result_table)

  
  @property
  def session_id(self):
    """Retourne l'identifiant de session
    
    Utilisé en particulier pour la journalisation dans la web console
    
    mpham 01/06/2022
    """
    return self.hreq.session_id
    
  
  @property
  def is_continuous_page(self):
    """ Indique si la page est de type continue
      (affichage progressif d'un bloc de la page)
    
    mpham 05/08/2024
    """
    return self.hreq.continuous_page


  def get_query_string_param(self, key, default=None):
    
    """
    retourne la valeur d'un paramètre de la query string
      le paramètre ne doit se retrouver qu'une fois dans la query string
      
    retourne None si le paramètre n'est pas trouvé ou s'il a plusieurs valeurs
    
    mpham 01/03/2021
    """

    value = default
    
    url_params = self.parse_query_string()

    if key in url_params:
      values = url_params[key]
      if len(values) == 1:
        value = values[0]
    
    return value
    
  
  def parse_query_string(self):
  
    url_items = urllib.parse.urlparse(self.hreq.path)
    return urllib.parse.parse_qs(url_items.query)
  
    
  def add_content(self, content):
    self.hreq.add_content(content)
    
  
  def send_page(self, content = '', code=200):
    self.hreq.send_page(content, code)


  def send_page_raw(self, content = ''):
    self.hreq.send_page_raw(content)


  def send_page_top(self, code = 200, template=True, send_cookie=True):
    self.hreq.send_page_top(code, template, send_cookie)

  def send_page_bottom(self):
    self.hreq.send_page_bottom()


  def add_html(self, html):
    self.hreq.add_html(html)

  def add_javascript(self, code):
    self.hreq.add_javascript(code)

  def add_javascript_include(self, url):
    self.hreq.add_javascript_include(url)


  def start_continuous_page_block(self):
    self.hreq.start_continuous_page_block()

  def end_continuous_page_block(self):
    self.hreq.end_continuous_page_block()


  def send_template(self, template_name:str, **parameters):
    self.hreq.send_template(template_name, **parameters)

  def send_template_raw(self, template_name:str, **parameters):
    self.hreq.send_template_raw(template_name, **parameters)    
  
  def send_redirection(self, url):
    self.hreq.send_redirection(url)
    
  def download_file(self, path:str, content_type:str='application/octet-stream', filename:str=None):
    self.hreq.download_file(path, content_type, filename)
 
  def send_json_page(self, html:str='', javascript:str=''):
    self.hreq.send_json_page(html, javascript)
    
  def send_json(self, url):
    self.hreq.send_json(url)
    
    
  def set_session_value(self, key, value):
    self.hreq.set_session_value(key, value)
    
    
  def get_session_value(self, key):
    return self.hreq.get_session_value(key)

    
  def del_session_value(self, key):
    self.hreq.del_session_value(key)


  def logon(self, idp_id, id_token = 'authenticated'):
    self.hreq.logon(idp_id, id_token)


  def logoff(self, idp_id):
    self.hreq.logoff(idp_id)


  def is_logged(self, idp_id):
    return self.hreq.is_logged(idp_id)


  def log_info(self, message):
    logging.info(message, extra={'sessionid': self.session_id})
    return message

    
  def log_error(self, message, level=0):
    logging.error(message, extra={'sessionid': self.session_id})
    return message


  def start_result_table(self):
    """ Commence un tableau de résultat
    
    On fait un test sur self.is_continuous_page le temps de la migration de toutes les pages vers le mode continu
    TODO : retirer les add_content quand toutes les pages seront en mode continu
    
    Versions:
      25/02/2021 (mpham) version initiale
      05/08/2024 (mpham) adaptation aux pages continues
    """
    
    if self.is_continuous_page:
      self.start_continuous_page_block()
      self.add_html('<table class="fixed">')
    else:
      self.add_content('<table class="fixed">')
    self.result_in_table = True
  

  def is_result_in_table(self):
    return self.result_in_table
    

  def row_label(self, label : str, help_id : str) -> str:
    
    """ Formate le titre d'une ligne avec une icône d'aide à droite
    
    :param str name: libellé de la ligne
    :param str help_id: identifiant relatif de la rubrique d'aide (l'identifiant est préfixé par la fonction Javascript help() locale)
    :return: code HTML à insérer dans le <td>
    :rtype: str
    
    .. note::
      mpham 22/04/2021
    """
    
    return '<span class="celltxt">{label}</span><span class="cellimg"><img onclick="help(this, \'{help_id}\')" src="/images/help.png"></span>'.format(label=html.escape(label), help_id=help_id)
    

  def add_result_row(self, title:str, value:str, help_id:str=None, copy_button=True, expanded=False):
    """
    Ajoute une ligne à un tableau de retour d'authentification
    Tronque la valeur si elle est trop longue (avec bouton d'affichage complet)
    Possibilité de copie de la valeur

    On fait un test sur self.is_continuous_page le temps de la migration de toutes les pages vers le mode continu
    TODO : retirer les add_content quand toutes les pages seront en mode continu
    
    Args:
      title: libellé de la ligne (colonne de droite)
      value: valeur à afficher (colonne de gauche)
      help_id: identifiant de la rubrique d'aide, None si on ne propose pas d'aide
      copy_button: affiche un bouton pour copier la valeur dans le presse-papier  
      expanded: indique si le texte est trop long s'il faut en afficher que le début (défaut) ou en entier
    
    Versions:
      25/02/2021 (mpham) version initiale
      29/09/2022 (mpham) col identifier is now a uuid be bu truely unique
      28/02/2023 (mpham) ajout de l'argument copy_button contrôlant l'affichage du bouton  de copie
      05/08/2024 (mpham) adaptation aux pages continues
      05/09/2024 (mpham) ajout de l'argument expanded
    """

    col_id = 'col' + str(uuid.uuid4())
    if help_id is None:
      row_label = html.escape(title)
    else:
      row_label = '<span class="celltxt">{label}</span><span class="cellimg"><img onclick="help(this, \'{help_id}\')" src="/images/help.png"></span>'.format(label=html.escape(title), help_id=help_id)
    if self.is_continuous_page:
      self.add_html('<tr><td>'+row_label)
      self.add_html('<span id="'+col_id+'_raw" style="display: none;">'+value+'</span>')
      self.add_html('</td>')
    else:
      self.add_content('<tr><td>'+row_label)
      self.add_content('<span id="'+col_id+'_raw" style="display: none;">'+value+'</span>')
      self.add_content('</td>')
    
    if len(value) <= 80:
      # la valeur tient sur une ligne
      html_value = html.escape(value).replace('\n', '<br>').replace(' ', '&nbsp;')
      if self.is_continuous_page:
        self.add_html('<td><span id="'+col_id+'"><span id="'+col_id+'c">'+html_value+'</span>')
        self.add_html('</td><td style="width: 34px;">')
      else:
        self.add_content('<td><span id="'+col_id+'"><span id="'+col_id+'c">'+html_value+'</span>')
        self.add_content('</td><td style="width: 34px;">')
      if copy_button:
        if self.is_continuous_page:
          self.add_html('<span> </span><img title="Copy value" class="smallButton" src="/images/copy.png" onClick="copyValue(\''+col_id+'\')"/></span>')
        else:
          self.add_content('<span> </span><img title="Copy value" class="smallButton" src="/images/copy.png" onClick="copyValue(\''+col_id+'\')"/></span>')
      if self.is_continuous_page:
        self.add_html('</td>')
      else:
        self.add_content('</td>')
    else:
      # la valeur doit être tronquée
      html_value = html.escape(value).replace('\n', '<br>').replace(' ', '&nbsp;')
      truncated_value = html.escape(value[0:80]+'...')
      if expanded:
        display_truncated = 'none'
        display_all = 'inline'
        display_minus = 'inline'
        display_plus = 'none'
      else:
        display_truncated = 'inline'
        display_all = 'none'
        display_minus = 'none'
        display_plus = 'inline'
      
      if self.is_continuous_page:
        self.add_html('<td><span id="'+col_id+'s" style="display: '+display_truncated+';">'+truncated_value+'</span>')
        self.add_html('<span id="'+col_id+'l" style="display: '+display_all+';"><span id="'+col_id+'c">'+html_value+'</span>')
        self.add_html('</td><td style="width: 34px;">')
        self.add_html('<span><img title="Expand" id="'+col_id+'_expand" class="smallButton"  style="display: '+display_plus+';" src="/images/plus.png" onClick="showLong(\''+col_id+'\')"/></span>')
        self.add_html('<img title="Collapse" id="'+col_id+'_collapse" class="smallButton" style="display: '+display_minus+';" src="/images/moins.png" onClick="showShort(\''+col_id+'\')"/>')
      else:
        self.add_content('<td><span id="'+col_id+'s" style="display: '+display_truncated+';">'+truncated+'</span>')
        self.add_content('<span id="'+col_id+'l" style="display: '+display_all+';"><span id="'+col_id+'c">'+html_value+'</span>')
        self.add_content('</td><td style="width: 34px;">')
        self.add_content('<span><img title="Expand" id="'+col_id+'_expand" class="smallButton"  style="display: '+display_plus+';" src="/images/plus.png" onClick="showLong(\''+col_id+'\')"/></span>')
        self.add_content('<img title="Collapse" id="'+col_id+'_collapse" class="smallButton" style="display: '+display_minus+';" src="/images/moins.png" onClick="showShort(\''+col_id+'\')"/>')
      if copy_button:
        if self.is_continuous_page:
          self.add_html('<span> </span><img title="Copy value" class="smallButton" src="/images/copy.png" onClick="copyValue(\''+col_id+'\')"/></span>')
        else:
          self.add_content('<span> </span><img title="Copy value" class="smallButton" src="/images/copy.png" onClick="copyValue(\''+col_id+'\')"/></span>')
      if self.is_continuous_page:
        self.add_html('</td>')
      else:
        self.add_content('</td>')
    if self.is_continuous_page:
      self.add_html('</tr>')
    else:
      self.add_content('</tr>')
    

  def end_result_table(self):
    """ Ferme un tableau de résultat
    
    On fait un test sur self.is_continuous_page le temps de la migration de toutes les pages vers le mode continu
    TODO : retirer les add_content quand toutes les pages seront en mode continu
    
    Versions:
      25/02/2021 (mpham) version initiale
      05/08/2024 (mpham) adaptation aux pages continues
    """
    
    if self.result_in_table:
      if self.is_continuous_page:
        self.add_html('</table>')
        self.end_continuous_page_block()
      else:
        self.add_content('</table>')
      self.result_in_table = True


  def escape_string_to_javascript(self, string:str) -> str:
    """ Ajoute des caractères d'échappement pour génération de chaînes dans du code Javascript
    
    Versions:
      mpham (05/09/2024) version initiale
    """
    return string.replace("'", r"\'").replace('"', r'\"').replace("\\", "\\\\")

    
  def _generate_unique_id(self, name:str, existing_ids:list, default:str='id', prefix=''):
    
    """
    Génère un identifiant à partir d'un nom
    en ne retenant que les lettres et les chiffres
    et en vérifiant que l'identifiant n'existe pas déjà
    
    S'il existe, ajoute un suffixe numérique

    Args:
      name: Nom à partir duquel l'identifiant est généré
      existing_ids: liste des identifiants qui existent déjà
      default: nom par défaut si aucun n'est donné
      prefix: préfixe de l'identifiant, qui sera donc de la forme <prefixe><nom> dans le cas général
      
    Returns:
      identifiant unique parmi une liste, de la forme <prefixe><nom> et avec ajout d'un indice pour gérer les doublons

    Versions:
      28/02/2021 (mpham) version initiale
      31/12/2024 (mpham) gestion des préfixes, pour obtenir des identifiants globalement uniques pour les IdP et les apps
    """
    
    name = default if name == '' else name
    base = prefix + ''.join(c for c in name.casefold() if c.isalnum())
    ok = False
    rank = 0
    
    while not ok:

      candidate_id = base + ('' if rank == 0 else str(rank))
      if candidate_id in existing_ids:
        rank = rank+1
      else:
        ok = True
        
    return candidate_id



class AduneoError(Exception):
  """ Exception fonctionnelle
  """
  
  def __init__(self, message:str, explanation_code:str=None, action:str=None, button_label:str=None):
    self.explanation_code = explanation_code
    self.action = action
    self.button_label = button_label
    super().__init__(message)


class DesignError(Exception):
  """ Erreur de conception
  """
  
  def __init__(self, message:str, explanation_code:str=None):
    self.explanation_code = explanation_code
    super().__init__(message)


class WebRouter:
  """
    URL registration
    
    Permet de créer automatiquement des URL dans des objets descendant de BaseHandler
    
    Cet objet (de parent BaseHandler) a le decorator @register_web_module qui en donne le chemin racine
    
    @register_web_module('/client/oauth/login')
    class OAuthClientLogin(BaseHandler):
    
    Les méthodes de l'objet devant servir des URL ont le decorator @register_page_url avec la méthode (une même URL ne peut donc pas servir en même temps GET et POST)
    
    @register_page_url('send_access_token_introspection_request', 'POST')
    def send_access_token_introspection_request_spa(self):

    L'URL est donnée relativement au module. 
    L'URL complète sera donc /client/oauth/login/send_access_token_introspection_request
    
    L'URL vide ('') correspond à la page d'accueil du module, c'est-à-dire à /client/oauth/login dans notre exemple

    Si l'URL n'est pas donnée dans le décorateur,
    Le nom de la méthode donne l'URL relative (ici send_access_token_introspection_request_spa)
    
    L'URL complète sera alors /client/oauth/login/send_access_token_introspection_request_spa
    
    Pour servir une URL, on commence par vérifier qu'elle existe par WebRouter.is_authorized_url
    Puis on crée un objet WebRouter avec l'URL et la méthode HTTP
    Finalement, on invoque la méthode serve_url en lui passant l'instance de BaseServer qui traite la requête

    if WebRouter.is_authorized_url(url_items.path, 'POST'):
      web_router = WebRouter(url_items.path, 'POST')
      try:
        web_router.serve_url(self)
      except AduneoError as error:
        self.send_page(str(error), clear_buffer=True)

    mpham 30/09/2022
  """

  """
    Membre statique donnant les informations pour le service des pages en fonction de l'URL et de la méthode
    {
      "GET/POST": {
        "/module/url/path": {
          "module": "module full name eg ClientFedID.OAuthClientLogin",
          "class": "class name eg OAuthClientLogin",
          "method": "class method eg send_access_token_introspection_request_spa"
        }
      }
    }
  """
  authorized_urls = {'get': {}, 'post': {}}

  """
    Structure temporaire nécessaire à la constructionn de authorized_urls car les decorator de fonction (méthode de classe) sont appelés avant ceux de classe
  
    {
      "GET/POST": {
        "module full name eg ClientFedID.OAuthClientLogin": {
          "relative url path eg path from /module/url/path": {
            "module": "module full name eg ClientFedID.OAuthClientLogin",
            "class": "class name eg OAuthClientLogin",
            "method": "class method eg send_access_token_introspection_request_spa"
          }
        }
      }
    }
  """
  temp_urls = {'get': {}, 'post': {}}

  def is_authorized_url(url, method):
    """ Indique si l'URL est gérée par web router
    
    Args:
      url: URL relative de la page, par exemple /client/oauth/login/send_access_token_introspection_request_spa
      method: méthode HTTP, actuellement uniquement GET et POST
    
    mpham 30/09/2022
    """
    return WebRouter.authorized_urls[method.casefold()].get(url) is not None


  def __init__(self, url:str, method:str):
    """ Constructeur
    
    mpham 30/09/2022
    """
    self.url = url
    self.method = method.casefold()
    pass

    
  def serve_url(self, hreq):
    """ Lance le service d'une URL
    
    Args:
      hreq: instance de BaseServer traitant la requête
    
    Versions:
      30/09/2022 (mpham) version initiale basée sur exec et eval
      30/01/2025 (mpham) récriture avec importlib, pour compatibilité Python 13
    """
    func_def = WebRouter.authorized_urls[self.method].get(self.url)
    if func_def:
      # comme is_authorized_url devrait être appelé avant, ce devrait toujours être vrai
      web_module = importlib.import_module(func_def['module']) # par exemple ClientFedID.OAuthClientLogin
      web_class = getattr(web_module, func_def['class']) # par exemple OAuthClientLogin
      web_instance = web_class(hreq)
      http_method = getattr(web_instance, func_def['method']) # par exemple prepare_request
      http_method()
    else:
      logging.error("Unknown URL "+self.url)


def register_url(method:str, url:str=None):
  """ Decorator pour les méthodes de classe
  
  Attention, ce décorateur doit être le dernier (se trouver le plus proche de la déclaration de la méthode), sinon il n'est pas pris en compte
    (l'enregistrement se fait pas car func n'est pas la page mais le décorateur suivant)
  
  Args:
    method: méthode HTTP
    url: URL relative par rapport à la racine déclarée au niveau de la classe par le décorateur register_web_module

  Versions:
    30/09/2022 (mpham) version initiale
  """
  def decorator(func):
  
    module_name = func.__module__
    class_name = func.__qualname__.split('.')[0]
    method_name = func.__qualname__.split('.')[1]
    
    relative_url = url

    if relative_url is None:
      relative_url = method_name
    if module_name not in WebRouter.temp_urls[method.casefold()]:
      WebRouter.temp_urls[method.casefold()][module_name] = {}
    WebRouter.temp_urls[method.casefold()][module_name][relative_url] = {'module': module_name, 'class': class_name, 'method': method_name}

    return func
    
  return decorator

  
def register_page_url(method:str, url:str=None, template:str=None, continuous:bool=False):
  """ Decorator de déclaration d'une page web représentée par une méthode de classe
  
  La méthode doit se trouver dans une classe décorée par @register_web_module
  
  Attention, ce décorateur doit être le dernier (se trouver le plus proche de la déclaration de la méthode), sinon il n'est pas pris en compte
    (l'enregistrement se fait pas car func n'est pas la page mais le décorateur suivant)
  
  Args:
    method: méthode HTTP, avec possibilité d'en donner plusieurs, dans une list (['GET', 'POST'] par exemple)
    url: URL relative par rapport à la racine déclarée au niveau de la classe par le décorateur register_web_module
    template: nom (optionnel) d'un fichier de modèle (du dossier templates) où le mot-clé {{content}} indique où insérer le contenu
    continuous: indique si la page est de type continu (envoi progressif du contenu pour affichage partiel lors des opérations prenant du temps)

  Versions:
    30/09/2022 (mpham) version initiale
    24/03/2023 (mpham) ajout de la fonction wrapper pour pouvoir ajouter d'autres décorateurs aux méthodes (en particulier @continuous_page)
    29/03/2023 (mpham) ajout des paramètres template et continuous
    05/01/2025 (mpham) possibilité de définir plusieurs méthodes
    09/01/2025 (mpham) comportement identique pages continues et non continues avec CfiForm
  """
  def decorator(func):
  
    # Enregistrement de l'URL
    module_name = func.__module__
    class_name = func.__qualname__.split('.')[0]
    method_name = func.__qualname__.split('.')[1]
    
    relative_url = url

    if relative_url is None:
      relative_url = method_name
    
    methods = method
    if isinstance(methods, str):
      methods = [methods]
    for met in methods:  
      if module_name not in WebRouter.temp_urls[met.casefold()]:
        WebRouter.temp_urls[met.casefold()][module_name] = {}
      WebRouter.temp_urls[met.casefold()][module_name][relative_url] = {'module': module_name, 'class': class_name, 'method': method_name}
    
    # Traitement de la page
    def wrapper(*args, **kwargs):

      from .Template import Template
    
      self = args[0] # correspond à l'objet de module héritant de BaseHandler
      
      template_content = '{{content}}'
      if template:
        from .Template import Template
        template_content = Template.load_template(template)
      
      self.hreq.continuous_page = continuous
      #print('---- IN DECORATOR', self.hreq.continuous_page)
      if continuous:
        
        # Page continue
        continuous_page_id = self.hreq.headers.get('CpId')
        if continuous_page_id:
          # on est en ajout de contenu d'une page à ajout progressif, on récupère l'identifiant existant
          self.hreq.continuous_page_id = continuous_page_id

          self.hreq.send_response(200)
          self.hreq._send_page_headers()
          self.hreq.top_sent = True # TODO, regarder comment le supprimer
          func(*args, **kwargs)
          
        else:
          # initialisation d'une page à ajout progressif, on affiche le template de la page
        
          self.hreq.continuous_page_id = str(uuid.uuid4())
          #print('---- IN DECORATOR', self.hreq.continuous_page_id)
          
          # TODO : transférer vers le template le presse-papiers et l'include requestSender
          from .WebModules.Clipboard import Clipboard
          content = Clipboard.get_window_definition()
          content += """
          <script src="/javascript/requestSender.js"></script>
          <div id="text_ph"></div>
          <div id="end_ph"></div>        
          <script>
          continuousPageId = '{cp_id}';
          function getHtmlJsonContinueDelayed() {{
            getHtmlJsonContinue("GET", "/continuouspage/poll?cp_id={cp_id}");
          }}
          //setTimeout(getHtmlJsonContinueDelayed, 1000);
          getHtmlJsonContinueDelayed()
          </script>
          """.format(cp_id=self.hreq.continuous_page_id)
        
          self.hreq.send_response(200)
          self.hreq._send_page_headers()
          self.hreq.top_sent = True # TODO, regarder comment le supprimer
          self.add_content(Template.apply_template(template_content, content=content))
          func(*args, **kwargs)
        
      else:
        # Page normale
        
        content_pos = template_content.find('{{content}}')
        if content_pos == -1:
          raise AduneoError(self.log_error("Le fichier de modèle de page "+template+" ne contient pas de balise de contenu {{content}}"))
        template_top = template_content[:content_pos+11]
        template_bottom = template_content[content_pos+11:]

        from .WebModules.Clipboard import Clipboard
        content = Clipboard.get_window_definition()
        content += """
        <script src="/javascript/requestSender.js"></script>
        """

        self.hreq.send_response(200)
        self.hreq._send_page_headers()
        self.hreq.top_sent = True # TODO, regarder comment le supprimer
        self.add_content(Template.apply_template(template_top, content=content))
        func(*args, **kwargs)
        self.add_content(template_bottom)
        #self.add_content(Template.apply_template(template_bottom))
        
    return wrapper
    
  return decorator


def register_api_url(method:str, url:str=None):
  """ Decorator de déclaration d'une API représentée par une méthode de classe
  
  La méthode doit se trouver dans une classe décorée par @register_web_module
  
  Attention, ce décorateur doit être le dernier (se trouver le plus proche de la déclaration de la méthode), sinon il n'est pas pris en compte
    (l'enregistrement se fait pas car func n'est pas la page mais le décorateur suivant)
  
  Args:
    method: méthode HTTP
    url: URL relative par rapport à la racine déclarée au niveau de la classe par le décorateur register_web_module

  Versions:
    30/09/2022 (mpham) version initiale
  """
  def decorator(func):
  
    # Enregistrement de l'URL
    module_name = func.__module__
    class_name = func.__qualname__.split('.')[0]
    method_name = func.__qualname__.split('.')[1]
    
    relative_url = url

    if relative_url is None:
      relative_url = method_name
    if module_name not in WebRouter.temp_urls[method.casefold()]:
      WebRouter.temp_urls[method.casefold()][module_name] = {}
    WebRouter.temp_urls[method.casefold()][module_name][relative_url] = {'module': module_name, 'class': class_name, 'method': method_name}

    return func
    
  return decorator


def register_web_module(path):
  """ Decorator pour les classes descendant de BaseHandler contenant des méthodes de service d'URL
  
  Args:
    path: URL relative servie par la classe, par exemple /client/oauth/login

  Versions:
    30/09/2022 (mpham) version initiale
    28/12/2023 (mpham) page d'accueil des modules
  """
  def decorator(class_def):
    module_name = class_def.__module__
    for method in ['get', 'post']:
      for relative_url in WebRouter.temp_urls[method.casefold()].get(module_name, []):
        if relative_url == '':
          full_url = path
        else:
          full_url = path+'/'+relative_url
        func_def = WebRouter.temp_urls[method.casefold()][module_name][relative_url]
        WebRouter.authorized_urls[method][full_url] = func_def
    
    return class_def
  return decorator
  
  
def continuous_page(html:str='', send_page_header:bool=True):

# En fait, au lieu de passer du html et d'avoir un flag d'envoi du template, il faudrait revoir le fonctionnement global des templates
#  pour avoir quelque chose de cohérent entre les pages normales et les pages continues
# Peut-être avoir un flag pour les deux ?Qu'on positionnerait dans le code ?
#   ou alors dans le register_url
#   et on pourrait supprimer le décorateur continuous_page pour le mettre dans register_url
#   (comme on a de toute façon des problèmes d'ordre dans les décorateurs)
#   Par exemple: @register_url('GET', '/chemin', template='default', continuous=True)
#
# d'ailleurs pourrait-on unifier le template de page avec les templates de contenu de page ?

# DEPRECATED

  """
  Les pages continues sont des pages qui s'affichent progressivement :
  - la méthode de la page fait des appel à self.add_content(str) pour ajouter des informations à envoyer
  - à chaque fois qu'elle souhaite envoyer les informations au navigateur, elle fait self.flush_content()
  - à la fin, elle fait send_page(str)
  
  Techniquement, il est envoyé au navigateur du code Javascript qui fait des appels réguliers (toutes les secondes) à l'URL /continuouspage/poll
  Cette page regarde s'il existe du contenu en attente et le cas échéant l'envoie
  Lors d'un send_page, /continuouspage/poll envoie une commande de FIN qui arrête le polling
  
  Déclaration :
  les pages continues ont le décorateur @continuous_page()
  
  Exemple :
    @continuous_page()
    @register_url(url='preparerequest', method='GET')
    def prepare_request_temp(self):

  
  Technique :
  les pages continues sont gérées par l'objet ContinuousPage qui
  - conserve le buffer
  - reçoit aux sollicitations de polling du navigateur
  - y répond avec le buffer quand ce dernier est libéré
  
  Un identifiant unique de page est généré par le décorateur pour établir une sorte de session de page et envoyer le contenu non seulement au bon navigateur
    (ce que ferait la session HTTP), mais au bon onglet dans le navigateur.
    Pour récupérer du contenu, une vérification double est effectuée : la session HTTP + l'identifiant de page continue
    (elle est nécessaire car l'identifiant de page continue est passé dans les requêtes, avec donc un risque d'interception)
  
  Un flag est mis dans l'objet BaseServer pour indiquer qu'on passe en mode continu et que le comportement doit être modifié:
  - flush_content, qui ne fait rien en mode normal, transmet alors le contenu vers ContinuousPage
  - send_page, au lieu d'envoyer toute la page, fait un flush_content avec fin de page
  
  Le décorateur @continuous_page met en place le flag dans BaseServer et envoie (si demandé) les en-têtes de la page
  
  24/03/2023 (mpham) version initiale
  """

  def decorator(func):
  
    def wrapper(*args, **kwargs):
    
      self = args[0] # correspond à l'objet de module héritant de BaseHandler
      
      cp_id = str(uuid.uuid4())
      
      self.add_content(html)
      
      self.add_content("""
      <div id="text_ph"></div>
      <div id="end_ph"></div>
      
      <script>""")
      self.add_content('getHtmlJsonContinue("GET", "/continuouspage/poll?cp_id="'+cp_id+')')
      self.add_content("""
      </script>
      """)
      self.send_page()
      
      self.hreq.continuous_page = True
      self.hreq.continuous_page_id = cp_id

      func(*args, **kwargs)
      
    return wrapper
    
  return decorator