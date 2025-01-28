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
from ..BaseServer import register_web_module, register_page_url
from ..BaseServer import BaseHandler
from ..Configuration import Configuration
from ..Context import Context
import html
import json
import requests
import urllib.parse
import uuid
import logging


@register_web_module('/client/flows')
class FlowHandler(BaseHandler):
  """ Classe de base des cinématiques SAML, OpenID Connect et OAuthClientLogin
  
  Contient les éléments communs :
  - gestion des requêtes
  - menu de pied de page
  
  Versions:
    23/12/2022 (mpham) : version initiale
  """

  def __init__(self, hreq):
    """ Constructeur
    
    Args:
      hreq: instance courante de HTTPRequestHandler
    
    Versions:
      23/12/2022 (mpham) version initiale
      08/08/2024 (mpham) l'objet de contexte est directement instancié ici
      30/12/2024 (mpham) en POST, on va aussi chercher l'identifiant du contexte dans hr_context (champ standard de RequesterForm)
    """

    super().__init__(hreq)
    
    self.context = None
    if hreq.command == 'GET':
      context_id = self.get_query_string_param('contextid')
    elif hreq.command == 'POST':
      context_id = self.post_form.get('contextid')
      if not context_id:
        context_id = self.post_form.get('hr_context')

    if context_id:
      self.context = self.get_session_value(context_id)

  
  @register_page_url(url='cancelrequest', method='GET', continuous=True)
  def cancel_request(self):
    """ Annule une requête affichée par display_form_http_request
    
    Versions:
      23/12/2022 (mpham) version initiale
      05/09/2024 (mpham) adaptation aux pages continues et à CfiForm
    """
    self.add_html("""<div>Action cancelled</div>""")
    self.add_menu()
    self.send_page()
  
  
  @register_page_url(url='newauth', method='GET', continuous=True)
  def new_auth(self):
    """ Menu de nouvelle authentification auprès d'une application de l'IdP courant, en poursuite de contexte
    
    Versions:
      04/12/2024 (mpham) version initiale
      28/01/2025 (mpham) CAS et SAML
    """
    self.add_html("""<h2>New auth in same context</h2>""")
    
    idp_id = self.context.idp_id
    idp = self.conf['idps'][idp_id]

    if idp.get('oidc_clients'):
      
      self.add_html("""<div>OIDC Clients</div>""")          
      for client_id in sorted(idp['oidc_clients'].keys()):
        
        client = idp['oidc_clients'][client_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}&newauth=true" class="smallbutton">Login</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
            context_id = self.context.context_id,
          )
        )

    if idp.get('oauth2_clients'):
        
      self.add_html("""<div>OAuth 2 Clients</div>""")          
      for client_id in sorted(idp['oauth2_clients'].keys()):
        
        client = idp['oauth2_clients'][client_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}&newauth=true" class="smallbutton">Login</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
            context_id = self.context.context_id,
          )
        )

    if idp.get('saml_clients'):
        
      self.add_html("""<div>SAML Service Providers (SP)</div>""")          
      for client_id in sorted(idp['saml_clients'].keys()):
        
        client = idp['saml_clients'][client_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/saml/login/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}&newauth=true" class="smallbutton">Login</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
            context_id = self.context.context_id,
          )
        )

    if idp.get('cas_clients'):
        
      self.add_html("""<div>CAS Clients</div>""")          
      for client_id in sorted(idp['cas_clients'].keys()):
        
        client = idp['cas_clients'][client_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/cas/login/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}&newauth=true" class="smallbutton">Login</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
            context_id = self.context.context_id,
          )
        )

    dom_id = 'id'+str(uuid.uuid4())
    self.add_html('<div id="'+html.escape(dom_id)+'">')
    self.add_html('<span onClick="fetchContent(\'GET\',\'/client/flows/cancelrequest?contextid='+urllib.parse.quote_plus(self.context.context_id)+'\', \'\', \''+dom_id+'\')" class="button">Cancel</span>')
    self.add_html('</div>')
    
    self.send_page()
  
  
  @register_page_url(url='logout', method='GET', continuous=True)
  def logout(self):
    """ Menu de déconnexion d'une application (OIDC, SAML ou CAS) de l'IdP courant, en poursuite de contexte
    
    Pour OAuth 2, faire une révocation de jetons
    
    TODO : SAML
    
    Versions:
      30/12/2024 (mpham) version initiale
      04/01/2025 (mpham) SAML logout
      28/01/2025 (mpham) CAS logout
    """
    self.add_html("""<h2>Logout</h2>""")
    
    idp_id = self.context.idp_id
    idp = self.conf['idps'][idp_id]

    # OpenID Connect
    if idp.get('oidc_clients'):
      
      self.add_html("""<div>OIDC Clients</div>""")          
      for client_id in sorted(idp['oidc_clients'].keys()):
        
        client = idp['oidc_clients'][client_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/oidc/logout/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}" class="smallbutton">Logout</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
            context_id = self.context.context_id,
          )
        )

    # SAML
    if idp.get('saml_clients'):
      
      self.add_html("""<div>SAML service providers (SP)</div>""")          
      for app_id in sorted(idp['saml_clients'].keys()):
        
        app_params = idp['saml_clients'][app_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/saml/logout/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}" class="smallbutton">Logout</a></span>
          </div>
          """.format(
            name = html.escape(app_params.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(app_id),
            context_id = self.context.context_id,
          )
        )

    # CAS
    if idp.get('cas_clients'):
      
      self.add_html("""<div>CAS clients</div>""")          
      for app_id in sorted(idp['cas_clients'].keys()):
        
        app_params = idp['cas_clients'][app_id]
        self.add_html("""
          <div>
            <span>{name}</span>
            <span><a href="/client/cas/logout/preparerequest?idpid={idp_id}&appid={app_id}&contextid={context_id}" class="smallbutton">Logout</a></span>
          </div>
          """.format(
            name = html.escape(app_params.get('name', 'Client')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(app_id),
            context_id = self.context.context_id,
          )
        )

    dom_id = 'id'+str(uuid.uuid4())
    self.add_html('<div id="'+html.escape(dom_id)+'">')
    self.add_html('<span onClick="fetchContent(\'GET\',\'/client/flows/cancelrequest?contextid='+urllib.parse.quote_plus(self.context.context_id)+'\', \'\', \''+dom_id+'\')" class="smallbutton">Cancel</span>')
    self.add_html('</div>')
    
    self.send_page()
  
  
  def display_http_request(self, method:str, url:str, data:dict = None, auth_method:str = 'None', auth_login:str = None, sender_url:str = None, context:str = None, dom_id=None):
    """ Affiche un formulaire avec une requête HTTP à envoyer
         - soit pour afficher une page (directement par le navigateur)
         - soit pour un appel d'API réalisé par ClientFedID
    
    L'utilisateur a le loisir de modifier l'URL, les données (en POST) et la méthode d'authentification
    
    Args:
      method (str): GET ou POST
      url (str): URL à appeler, avec la query string
      data (dict): données à envoyer en POST
      auth_method: None ou Basic
      auth_login: en authentification Basic, le login (le mot de passe est soit saisi dans l'interface, soit récupéré de la configuration)
      sender_url : cas des API, URL de FedClientID qui réalise l'appel de service web et qui doit donc récupérer les paramètres
      context: toujours dans le cas des API, paramètre  pour retrouver des informations de contexte lorsque sender_url reçoit les paramètres (souvent un objet request en session)
      dom_id: un préfixe pour les éléments HTML pour que le reste de la page puisse interagir avec le formulaire
      
      Elements HTML accessibles en Javascript (donner un dom_id) :
       - <dom_id>_i_url : champ caché conservant l'URL initiale, pour réinitialisation par le bouton "Reinit request"
       - <dom_id>_i_data : champ caché conservant les données initiales (au format JSON), pour réinitialisation par le bouton "Reinit request"
       - <dom_id>_d_url : champ visible et modifiable par l'utilisateur, contenant l'URL qui sera utilisée pour la constitution de la requête
       - <dom_id>_d_data : champ visible et modifiable par l'utilisateur, contenant les données (au format JSON) qui seront utilisées pour la constitution de la requête
        
    mpham 30/09/2022
    """

    if not dom_id:
      dom_id = str(uuid.uuid4())
    login = auth_login if auth_login else ''
    
    self.add_content('<input id="'+html.escape(dom_id)+'_i_url" type="hidden" value="'+html.escape(url)+'" />')
    if method == 'POST':
      self.add_content('<input id="'+html.escape(dom_id)+'_i_data" type="hidden" value="'+html.escape(json.dumps(data, indent=2))+'" />')
    self.add_content('<input id="'+html.escape(dom_id)+'_i_auth_method" type="hidden" value="'+html.escape(auth_method)+'" />')
    self.add_content('<input id="'+html.escape(dom_id)+'_i_auth_login" type="hidden" value="'+html.escape(auth_login)+'" />')
    if sender_url:
      self.add_content('<input id="'+html.escape(dom_id)+'_sender_url" type="hidden" value="'+html.escape(sender_url)+'" />')
      self.add_content('<input id="'+html.escape(dom_id)+'_context" type="hidden" value="'+html.escape(context)+'" />')
      
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>'+self.row_label('Request URL', 'request_url')+'</td><td><input id="'+html.escape(dom_id)+'_d_url" value="'+html.escape(url)+'"class="intable" type="text"></td></tr>')
    if method == 'POST':
      self.add_content('<tr><td>'+self.row_label('Request data', 'request_data')+'</td><td><textarea id="'+html.escape(dom_id)+'_d_data" rows="4" class="intable">'+html.escape(json.dumps(data, indent=2))+'</textarea></td></tr>')

    # HTTP authentification is only displayed when calling an API
    if sender_url:
      self.add_content('<tr><td>'+self.row_label('HTTP authentication', 'http_authentication')+'</td><td><select id="'+html.escape(dom_id)+'_d_auth_method" class="intable" onchange="changeRequestHTTPAuth(\''+html.escape(dom_id)+'\')">')
      for value in ('None', 'Basic'):
        selected = ''
        if value.casefold() == auth_method.casefold():
          selected = ' selected'
        self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
      self.add_content('</td></tr>')
      
      login_visible = (auth_method.casefold() == 'basic')
      login_visible_style = 'table-row' if login_visible else 'none'
      self.add_content('<tr id="'+html.escape(dom_id)+'_tr_auth_login" style="display: '+login_visible_style+';"><td>'+self.row_label('HTTP login', 'http_login')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_login" value="'+html.escape(login)+'" class="intable" type="text"></td></tr>')
      self.add_content('<tr id="'+html.escape(dom_id)+'_tr_auth_secret" style="display: '+login_visible_style+';"><td>'+self.row_label('HTTP secret', 'http_secret')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_secret" class="intable" type="password"></td></tr>')

    self.add_content('</table>')

    self.add_content('<div id="'+html.escape(dom_id)+'_button_bar">')
    self.add_content('<span class="middlebutton" onClick="reinitRequest(\''+html.escape(dom_id)+'\')">Reinit request</span>')
    if sender_url:
      self.add_content('<span class="middlebutton" onClick="sendRequest(\''+html.escape(dom_id)+'\')">Send request</span>')
    self.add_content('</div>')
    self.add_content('<div id="'+html.escape(dom_id)+'_send_notification" style="display: none;">')
    self.add_content('<h4>Sending request...</h4>')
    self.add_content('</div>')
    

  def display_form_http_request(self, method:str, url:str, table:dict = None, data_generator:str = 'return null;', http_parameters:dict = None, sender_url:str = None, context:str = None, dom_id:str=None, verify_certificates:bool=True):
    """ Affiche un formulaire avec une requête HTTP à envoyer
          pour un appel d'API réalisé par le front ClientFedID
          
    Doit être appelé dans une fonction elle-même déclenchée par un Javascript getHtmlJson (affichage en mode SPA)

    Les données de la requêtes sont pilotées :
      - soit par un formulaire affiché d'après les éléments donnés dans l'argument table
      - soit dans une zone de saisie contenant les données brutes

    Les éléments de construction du formulaire sont dans le dic table avec
      - title : nom du formulaire
      - fields : champs donnés dans une list dont les éléments sont des dict
        - name : nom de la donnée
        - label : libellé du champ
        - help_id : référence du texte d'aide donné dans help.json (TODO)
        - clipboard_category: catégorie de presse-papier, pour les champs texte uniquement, #name pour une reprise du nom
        - type : nature du champ
          - display_text : texte en lecture seule
          - edit_text : texte en modification
          - (ajouter en fonction des besoins edit_json, edit_textarea, edit_select, edit_checkbox, etc.)
        - value : valeur par défaut

    Les données de la requête sont mises à jour automatiquement lorsque des valeurs des <input> dont l'identifiant commence par <dom_id>_ sont modifiées (par exemple 424986_scope
    Pour cela, il doit être fourni le code Javascript de génération, qui retourne (dans return) les données.
      Dans ce code, les valeurs sont récupérées par la fonction get_form_value_with_dom qui prend en argument l'identifiant de l'<input> sans le dom
    
    Par exemple :
      data = {'scope': get_form_value_with_dom(domId, 'scope')};
      return data;
      
    Ces informations sont mises dans le corps en POST, et en query string en GET.

    L'utilisateur a le loisir de modifier l'URL, les données (en POST) et la méthode d'authentification (mais les modifications sont écrasées s'il modifie des <input>
    
    Args:
      method (str): GET ou POST
        on peut laisser le choix de la méthode par l'utilisateur, en donnant plusieurs méthodes séparées par des virgules. La première sera la méthode par défaut
      url (str): URL à appeler, avec la query string
      table: éléments à afficher, en lecture seule ou modification
      data_generator (dict): code Javascript générant les données à envoyer en POST en fonction des <input> commençant par <dom_id>_
      http_parameters (dict): options de la requête HTTTP
        url_label (str): libellé de l'URL, par défaut "Request URL"
        url_clipboard_category: catégorie pour le presse-papier (si non donné, le presse-papier n'est pas affiché)
        auth_method: None, POST ou Basic, défaut None
        auth_login: en authentification Basic ou POST, le login (le mot de passe est soit saisi dans l'interface, soit récupéré de la configuration)
      sender_url: cas des API, URL de FedClientID qui réalise l'appel de service web et qui doit donc récupérer les paramètres
      context: toujours dans le cas des API, paramètre  pour retrouver des informations de contexte lorsque sender_url reçoit les paramètres (souvent un objet request en session)
      dom_id: un préfixe pour les éléments HTML pour que le reste de la page puisse interagir avec le formulaire
      verify_certificates: indique la position initiale de la checkbox correspondante
      
      Elements HTML accessibles en Javascript (donner un dom_id) :
       - <dom_id>_d_url : champ visible et modifiable par l'utilisateur, contenant l'URL qui sera utilisée pour la constitution de la requête
          avec une valeur par défaut defaultValue
       - <dom_id>_d_data : champ visible et modifiable par l'utilisateur, contenant les données (au format JSON) qui seront utilisées pour la constitution de la requête
    
    Versions:
      14/12/2022 (mpham) : version initiale
      28/12/2022 (mpham) : presse-papier
      22/02/2023 (mpham) : prise en compte de la méthode (avant on n'était compatible qu'avec POST)
      23/02/2023 (mpham) : possibilité pour l'utilisateur de choisir la méthode, en en donnant plusieurs dans l'argument method
    """
    
    html_code = ''
    javascript = ''
    
    if not dom_id:
      dom_id = str(uuid.uuid4())
    dom_id = 'i'+dom_id.replace('-', '_') # car on utilise dom_id dans le nom de fonctions Javascript, et document.querySelectorAll n'aime pas les classes commençant par un chiffre

    self.log_info('Display form '+table['title'])
    html_code += "<h2>"+table['title']+"</h2>"

    html_code += '<form id="form-'+html.escape(dom_id)+'">'
    
    # Formulaire fonctionnel
    html_code += '<table class="fixed">'
    try:
      
      for field in table['fields']:
        html_code += '<tr><td>'+self.row_label(field['label'], field['help_id'])+'</td><td>'
        if field['type'] == 'edit_text':
          clipboard = ''
          if field.get('clipboard_category'):
            clipboard = ' data-clipboardcategory="'+field['clipboard_category']+'"'
          html_code += '<input id="'+html.escape(dom_id)+'_d_'+field['name']+'" value="'+html.escape(field['value'])+'" defaultValue="'+html.escape(field['value'])+'" class="intable '+dom_id+'" type="text"'+clipboard+'>'
        elif field['type'] == 'display_text':
          html_code += html.escape(field['value'])
        html_code += '<td>'
        if field.get('clipboard_category'):
          html_code += '<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>'
        html_code += '</td>'
        html_code += '</td></tr>'

    finally:
      html_code += '</table>'

    # Formulaire technique
    html_code += "<h3>Request for "+table['title']+"</h3>"

    if not http_parameters:
      http_parameters = {}
    default_http_parameters = {
        'auth_method': 'None',
        'auth_login': '',
        'url_label': None,
        'url_clipboard_category': None,
        }
    for item in default_http_parameters:
      if item not in http_parameters:
        http_parameters[item] = default_http_parameters[item]

    if sender_url:
      html_code += '<input id="'+html.escape(dom_id)+'_sender_url" type="hidden" value="'+html.escape(sender_url)+'" />'
      html_code += '<input id="'+html.escape(dom_id)+'_context" type="hidden" value="'+html.escape(context)+'" />'
    
    html_code += '<table class="fixed">'

    clipboard = ''
    if http_parameters:
      clipboard_category = http_parameters.get('url_clipboard_category')
      if clipboard_category:
        clipboard = ' data-clipboardcategory="'+html.escape(clipboard_category)+'"'
    html_code += '<tr><td>'+self.row_label('Request URL' if http_parameters['url_label'] == None else http_parameters['url_label'], 'request_url')+'</td><td><input id="'+html.escape(dom_id)+'_d_url" value="'+html.escape(url)+'" defaultValue="'+html.escape(url)+'" class="intable" type="text"'+clipboard+'></td>'
    html_code += '<td>'
    if clipboard != '':
      html_code += '<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>'
    html_code += '</td>'
    html_code += '</td></tr>' # TODO : il n'y a pas un </td> en trop ?
    
    methods = [m.strip().upper() for m in method.split(',')]
    for m in methods:
      if m not in ['GET','POST']:
        raise AduneoError(self.log_error("HTTP method "+m+" not supported"))
    if len(methods) == 1:
      # une seule méthode, on passe en champ masqué
      html_code += '<input id="'+html.escape(dom_id)+'_method" type="hidden" value="'+html.escape(method)+'" />'
    else:
      # l'utilisateur peut choisir la méthode
      html_code += '<tr><td>HTTP method</td><td><select id="'+html.escape(dom_id)+'_method" class="intable" onchange="f_'+dom_id+'_update()">'
      for m in methods:
        html_code += '<option value="'+html.escape(m)+'">'+html.escape(m)+'</option>'
      html_code += '</td></tr>'
    
    html_code += '<tr id="'+html.escape(dom_id)+'_tr_request_data"><td>'+self.row_label('Request data', 'request_data')+'</td><td><textarea id="'+html.escape(dom_id)+'_d_data" rows="4" class="intable"></textarea></td><td></td></tr>'

    # HTTP authentification is only displayed when calling an API
    if sender_url:
      html_code += '<tr><td>'+self.row_label('Call authentication', 'http_authentication')+'</td><td><select id="'+html.escape(dom_id)+'_d_auth_method" defaultValue="'+html.escape(http_parameters['auth_method'])+'" class="intable" onchange="changeRequestHTTPAuth(\''+html.escape(dom_id)+'\')">'
      for value in ('None', 'Basic', 'POST', 'Bearer token'):
        selected = ''
        if value.casefold() == http_parameters['auth_method'].casefold():
          selected = ' selected'
        html_code += '<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>'
      html_code += '</td><td></td></tr>'
      
      login_visible = (http_parameters['auth_method'].casefold() in ['basic', 'post', 'bearer token'])
      login_visible_style = 'table-row' if login_visible else 'none'
      html_code += '<tr id="'+html.escape(dom_id)+'_tr_auth_login" style="display: '+login_visible_style+';"><td>'+self.row_label('HTTP login', 'http_login')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_login" value="'+html.escape(http_parameters['auth_login'])+'" defaultValue="'+html.escape(http_parameters['auth_login'])+'" class="intable" type="text" data-clipboardcategory="client_id"></td>'
      html_code += '<td><span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span></td></tr>'
      secret_visible = (http_parameters['auth_method'].casefold() in ['basic', 'post'])
      secret_visible_style = 'table-row' if secret_visible else 'none'
      remember_secrets = Configuration.is_parameter_on(self.conf, '/preferences/clipboard/remember_secrets', False)
      clipboard = ' data-clipboardcategory="client_secret!"' if remember_secrets else ''
      html_code += '<tr id="'+html.escape(dom_id)+'_tr_auth_secret" style="display: '+secret_visible_style+';"><td>'+self.row_label('Secret', 'http_secret')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_secret" defaultValue="" class="intable" type="password"'+clipboard+'></td>'
      html_code += '<td>'
      if clipboard != '':
        html_code += '<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>'
      html_code += '</td><tr>'
      verify_cert_checked = " checked" if verify_certificates else ''
      verify_cert_default_checked = " defaultChecked" if verify_certificates else ''
      html_code += '<tr id="'+html.escape(dom_id)+'_tr_verify_cert"><td>'+self.row_label('Verify certificate', 'verify_certificate')+'</td><td><input id="'+html.escape(dom_id)+'_d_verify_cert" type="checkbox" '+verify_cert_checked+'></td><td></td></tr>'

    html_code += '</table>'
    
    html_code += '</form>'

    html_code += '<div id="'+html.escape(dom_id)+'_button_bar">'
    html_code += '<span class="middlebutton" onClick="reinitRequest(\''+html.escape(dom_id)+'\')">Reinit request</span>'
    if sender_url:
      html_code += '<span class="middlebutton" onClick="sendRequest(\''+html.escape(dom_id)+'\')">Send request</span>'
    html_code += '<span class="middlebutton" onClick="cancelRequest(\''+html.escape(dom_id)+'\', \''+html.escape(context)+'\')">Cancel</span>'
    html_code += '</div>'
    html_code += '<div id="'+html.escape(dom_id)+'_send_notification" style="display: none;">'
    html_code += '<h3>Sending request...</h3>'
    html_code += '</div>'
    
    javascript += """
      function f_"""+dom_id+"""_fetch_data(domId) {"""+data_generator+"""}

      function f_"""+dom_id+"""_update() {
        let method = document.getElementById('"""+dom_id+"""_method').value
        
        if (method == 'GET') {
          document.getElementById('"""+dom_id+"""_tr_request_data').style.display = 'none';
          f_"""+dom_id+"""_update_get()
        } else if (method == 'POST') {
          document.getElementById('"""+dom_id+"""_tr_request_data').style.display = 'table-row';
          f_"""+dom_id+"""_update_post()
        }
      }

      function f_"""+dom_id+"""_update_get() {
        let data = f_"""+dom_id+"""_fetch_data('"""+dom_id+"""');
        
        queryString = ""
        if (data) {
          for (const [key, value] of Object.entries(data)) {
            if (queryString != "") { queryString += "&" }
            queryString += encodeURI(key) + "=" + encodeURI(value);
          }
        }
        if (queryString != "") {
          let url = document.getElementById('"""+dom_id+"""_d_url').defaultValue;
          if (url.includes('?')) {
            url += '&' + queryString;
          } else {
            url += '?' + queryString;
          }
          document.getElementById('"""+dom_id+"""_d_url').value = url;
        }
      }

      function f_"""+dom_id+"""_update_post() {
        let data = f_"""+dom_id+"""_fetch_data('"""+dom_id+"""');
        if (data === null) { data = {} }
        if (document.getElementById('"""+dom_id+"""_d_auth_method').value == 'POST') {
          data['client_id'] = document.getElementById('"""+dom_id+"""_d_auth_login').value
          data['client_secret'] = '********'
        }
        
        document.getElementById('"""+dom_id+"""_d_data').value = JSON.stringify(data, null, 2);
      }

      f_"""+dom_id+"""_update();
    """
      
    javascript += "document.getElementById('"+dom_id+"_d_auth_login').addEventListener('keyup', f_"+dom_id+"_update);"
    for field in table['fields']:
      if field['type'] == 'edit_text':
        javascript += "document.getElementById('"+dom_id+"_d_"+field['name']+"').addEventListener('keyup', f_"+dom_id+"_update);"
      elif field['type'].startswith('edit_'):
        javascript += "document.getElementById('"+dom_id+"_d_"+field['name']+"').addEventListener('change', f_"+dom_id+"_update);"

    self.send_json({'html': html_code, 'javascript': javascript})
        
    
  def send_form_http_request(self, default_secret=None):
    """ Envoie une requête préparée par display_form_http_request
    
      Args:
        default_secret: secret à utiliser s'il n'a pas été saisi dans le formulaire
        
      Returns:
        réponse de requests
    
      Versions:
        14/12/2022 (mpham) : version initiale
        22/02/2023 (mpham) : prise en compte de la méthode HTTP (avant on n'était compatible qu'avec POST)
    """
    
    state = self.post_form.get('context')
    if state is None:
      raise AduneoError(self.log_error("tracking identifier (state) not found in request"))
    self.log_info("  for state "+state)
    
    request = self.get_session_value(state)
    if (request is None):
      raise AduneoError(self.log_error('state not found in session'))

    # méthode HTTP de la requête à envoyer
    method = self.post_form.get('method')
    if method is None:
      raise AduneoError(self.log_error("HTTP method not found in request"))
    self.log_info("  HTTP method "+method)

    # callParameters contient les valeurs du formulaire (url, data, auth_method, auth_login, auth_secret, verify_cert). C'est un JSON constité par la méthode Javascript sendRequest
    call_parameters_string = self.post_form.get('callParameters')
    if call_parameters_string is None:
      raise AduneoError(self.log_error("service parameters not found in request"))
    self.log_info("  call parameters "+call_parameters_string)
    
    call_parameters = json.loads(call_parameters_string)
    
    self.start_result_table()
    
    service_endpoint = call_parameters.get('url')
    if service_endpoint is None:
      raise AduneoError(self.log_error("service URL not found in request"))
    
    service_request_string = call_parameters.get('data')
    service_request = None
    if service_request_string is not None and service_request_string != '':
      service_request = json.loads(service_request_string)
      
    auth_method = call_parameters.get('auth_method')
    if auth_method is None:
      raise AduneoError(self.log_error("Call authentication scheme not found in request"))
    
    auth_login = call_parameters.get('auth_login', '')
    auth_secret = call_parameters.get('auth_secret', '')
    if auth_secret == '':
      auth_secret = default_secret
      
    request_auth = None
    request_headers = None
    if auth_method.casefold() == 'basic':
      request_auth = (auth_login, auth_secret)
    elif auth_method.casefold() == 'post':
      service_request['client_id'] = auth_login
      service_request['client_secret'] = auth_secret
    elif auth_method.casefold() == 'bearer token':
      request_headers = {'Authorization':"Bearer "+auth_login}
    else:
      raise AduneoError(self.log_error("authentication scheme "+auth_method+" not supported"))

    verify_cert = call_parameters.get('verify_cert')
    if verify_cert is None:
      raise AduneoError(self.log_error("certificate verification flag not found in request"))

    self.add_content('<tr><td>Submitting request...</td>')
    self.log_info("Submitting request")
    try:
      self.log_info(('  ' * 1)+"Connecting to "+service_endpoint)
      self.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_cert else "disabled"))
      if method == 'GET':
        response = requests.get(service_endpoint, headers=request_headers, auth=request_auth, verify=verify_cert)
      elif method == 'POST':
        response = requests.post(service_endpoint, data=service_request, headers=request_headers, auth=request_auth, verify=verify_cert)
      else:
        raise AduneoError(self.log_error("HTTP method "+method+" not supported"))
    except Exception as error:
      self.add_content('<td>Error : '+str(error)+'</td></tr>')
      raise AduneoError(self.log_error(('  ' * 1)+'http service error: '+str(error)))
    if response.status_code == 200:
      self.add_content('<td>OK</td></tr>')
    else:
      self.add_content('<td>Error, status code '+str(response.status_code)+'</td></tr>')
      raise AduneoError(self.log_error('http service error: status code '+str(response.status_code)+", "+response.text))
      
    return response


  def add_menu(self):
    """ Affiche un menu en fin de cinématique pour
        - relancer une même cinématique
        - manipuler les jetons (introspection, user info, échanges), en fonction des jetons trouvés dans la session
        
    Args:
      context: contexte de la cinématique en cours, récupérée de la session
      
    Versions:
      08/08/2024 (mpham) version initiale
      30/12/2024 (mpham) logout
      28/01/2025 (mpham) CAS
    """

    if not self.context:
      self.add_html('<span><a href="/" class="button">Menu</a></span>')
    else:

      dom_id = 'id'+str(uuid.uuid4())

      context_id = self.context['context_id']
      
      userinfo = False
      logout = False
      introspection = False
      refresh = False
      token_exchange = False
      oauth_exchange = False
      
      for id_token in self.context['id_tokens'].values():
        userinfo = True
        logout = True
        token_exchange = True
        if 'access_token' in id_token:
          introspection = True
        if 'refresh_token' in id_token:
          refresh = True
      
      for access_token in self.context['access_tokens'].values():
        introspection = True
        token_exchange = True
        if 'refresh_token' in access_token:
          refresh = True

      if len(self.context['access_tokens']) > 0:
        oauth_exchange = True

      for saml_assertion_wrapper in self.context['saml_assertions'].values():
        logout = True
      
      for cas_ticket in self.context['cas_tickets'].values():
        logout = True
      
      retry_url = {
        'OIDC': '/client/oidc/login/preparerequest',
        'OAuth2': '/client/oauth2/login/preparerequest',
        'SAML': '/client/saml/login/preparerequest',
        'CAS': '/client/cas/login/preparerequest',
        }.get(self.context['flow_type'])

      self.add_html('<div id="'+html.escape(dom_id)+'">')
      if retry_url:
        self.add_html('<span><a href="'+retry_url+'?contextid='+urllib.parse.quote_plus(context_id)+'&idpid='+urllib.parse.quote_plus(self.context.idp_id)+'&appid='+urllib.parse.quote_plus(self.context.app_id)+'" class="middlebutton">Retry original flow</a></span>')
      self.add_html('<span onClick="fetchContent(\'GET\',\'/client/flows/newauth?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">New auth</span>')
      if userinfo:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oidc/userinfo/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Userinfo</span>')
      if introspection:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/introspection/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Introspect AT</span>')
      if refresh:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/refresh/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Refresh AT</span>')
      if logout:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/flows/logout?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Logout</span>')
      if token_exchange:
        self.add_html('<span onClick="getHtmlJson(\'GET\',\'/client/oauth/login/tokenexchange_spa?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Exchange Token</span>')
      if oauth_exchange:
        self.add_html('<span onClick="getHtmlJson(\'GET\',\'/client/saml/login/oauthexchange_spa?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+urllib.parse.quote_plus(dom_id)+'\')" class="middlebutton">Exchange SAML -> OAuth</span>')
      self.add_html('</div>')
