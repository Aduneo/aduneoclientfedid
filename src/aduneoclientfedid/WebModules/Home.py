"""
Copyright 2024 Aduneo

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
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url, register_page_url
from ..Configuration import Configuration
import html
import urllib.parse
import uuid


@register_web_module('/')
class Home(BaseHandler):

  @register_page_url(url='', method='GET', template='page_default.html')
  def homepage(self):
    """ Page d'accueil

    Versions:
      08/08/2024 (mpham) version initiale
      23/01/2024 (mpham) on n'affiche les éléments relatifs à SAML que si les saml_prerequisite sont vérifiés
      24/01/2024 (mpham) CAS client
    """

    idps = self.conf['idps']

    self.add_html("""
      <div>
        <span><a href="/client/oidc/admin/modifyclient" class="middlebutton">Add OIDC Client</a></span>
        <span><a href="/client/oauth2/admin/modifyclient" class="middlebutton">Add OAuth 2 Client</a></span>
    """)
    if self.hreq.saml_prerequisite:
      self.add_html("""
        <span><a href="/client/saml/admin/modifyclient" class="middlebutton">Add SAML SP</a></span>
      """)
    self.add_html("""
        <span><a href="/client/cas/admin/modifyclient" class="middlebutton">Add CAS Client</a></span>
      </div>
    """)

    for idp_id in sorted(idps.keys()):
      
      idp = idps[idp_id]

      opened = False
      self.add_html("""
        <div id="{section_id}" style="display: flex; margin-top: 2px; margin-bottom: 2px;">
          <span style="display: inline-block; width: 20px; vertical-align: top; padding-top: 6px;">
            <img class="plus_button" src="/images/plus.png" title="Expand" style="display: {plus_display}" onclick="expandSection(\'{section_id}\')">
            <img class="minus_button" src="/images/moins.png" title="Collapse" style="display: {minus_display}" onclick="collapseSection(\'{section_id}\')">
          </span>
          <span style="display: inline-block; vertical-align: top; width: 100%; border-bottom-style: solid; border-bottom-width: 1px; padding: 2px 2px 2px 2px;">
            <span class="homeIdp">{title}</span>
            <span class="section_content" style="display: {display};">
              <div>
                <span><a href="/client/idp/admin/display?idpid={idp_id}" class="smallbutton">Display IdP Parameters</a></span>
                <span><a href="/client/idp/admin/modify?idpid={idp_id}" class="smallbutton">Modify IdP Parameters</a></span>
              </div>
              <div>
        """.format(
          section_id = uuid.uuid4(),
          title = html.escape(idp.get('name', 'IDP')),
          plus_display = 'none' if opened else 'block',
          minus_display = 'block' if opened else 'none',
          display = 'block' if opened else 'none',
          idp_id = urllib.parse.quote_plus(idp_id),
        )
      )

      # clients (OP) OpenID Connect
      if idp.get('oidc_clients'):
        
        self.add_html("""<div style="font-size: 14px">OIDC OP (clients)</div>""")          
        for client_id in sorted(idp['oidc_clients'].keys()):
          
          client = idp['oidc_clients'][client_id]
          self.add_html("""
            <div style="font-size: 14px; margin-left: 20px;">
              <span>{name}</span>
              <span><a href="/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
              <span><a href="/client/oidc/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Config</a></span>
            </div>
            """.format(
              name = html.escape(client.get('name', 'Client')),
              idp_id = urllib.parse.quote_plus(idp_id),
              app_id = urllib.parse.quote_plus(client_id),
            )
          )

      # clients OAuth 2
      if idp.get('oauth2_clients'):
        
        self.add_html("""<div style="font-size: 14px">OAuth 2 Clients</div>""")          
        for client_id in sorted(idp['oauth2_clients'].keys()):
          
          client = idp['oauth2_clients'][client_id]
          self.add_html("""
            <div style="font-size: 14px; margin-left: 20px;">
              <span>{name}</span>
              <span><a href="/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
              <span><a href="/client/oauth2/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Config</a></span>
            </div>
            """.format(
              name = html.escape(client.get('name', 'Client')),
              idp_id = urllib.parse.quote_plus(idp_id),
              app_id = urllib.parse.quote_plus(client_id),
            )
          )

      # SP SAML
      if self.hreq.saml_prerequisite and idp.get('saml_clients'):
        
        self.add_html("""<div style="font-size: 14px">SAML SP</div>""")          
        for app_id in sorted(idp['saml_clients'].keys()):
          
          app_params = idp['saml_clients'][app_id]
          self.add_html("""
            <div style="font-size: 14px; margin-left: 20px;">
              <span>{name}</span>
              <span><a href="/client/saml/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
              <span><a href="/client/saml/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Config</a></span>
            </div>
            """.format(
              name = html.escape(app_params.get('name', 'SP')),
              idp_id = urllib.parse.quote_plus(idp_id),
              app_id = urllib.parse.quote_plus(app_id),
            )
          )

      # clients CAS
      if idp.get('cas_clients'):
        
        self.add_html("""<div style="font-size: 14px">CAS Clients</div>""")          
        for client_id in sorted(idp['cas_clients'].keys()):
          
          client = idp['cas_clients'][client_id]
          self.add_html("""
            <div style="font-size: 14px; margin-left: 20px;">
              <span>{name}</span>
              <span><a href="/client/cas/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
              <span><a href="/client/cas/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Config</a></span>
            </div>
            """.format(
              name = html.escape(client.get('name', 'Client')),
              idp_id = urllib.parse.quote_plus(idp_id),
              app_id = urllib.parse.quote_plus(client_id),
            )
          )

      self.add_html("""
              </div>
            </span>
          </span>
        </div>
        """)

