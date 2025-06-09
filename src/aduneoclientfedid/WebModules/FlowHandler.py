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
    
    if not self.context:
      self.add_html("""IdP context not found
        <div>
          <span><a href="/" class="smallbutton">Home</a></span>
        </div>
      """)

    else:
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
      revocation = False
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
        revocation = True
        token_exchange = True
        if 'refresh_token' in access_token:
          refresh = True

      if len(self.context['saml_assertions']) > 0:
        oauth_exchange = True
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
      if revocation:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/revocation/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Revoke AT</span>')
      if refresh:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/refresh/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Refresh AT</span>')
      if logout:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/flows/logout?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Logout</span>')
      if token_exchange:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/tokenexchange/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+dom_id+'\')" class="middlebutton">Exchange token</span>')
      if oauth_exchange:
        self.add_html('<span onClick="fetchContent(\'GET\',\'/client/oauth2/samltoat/preparerequest?contextid='+urllib.parse.quote_plus(context_id)+'\', \'\', \''+urllib.parse.quote_plus(dom_id)+'\')" class="middlebutton">Exchange SAML -> OAuth</span>')
      self.add_html('</div>')
