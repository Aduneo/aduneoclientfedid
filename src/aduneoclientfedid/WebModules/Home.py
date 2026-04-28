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

    self.add_html("""<link rel="stylesheet" href="/css/home.css">""")

    self.add_html("<div>")
    
    self.dropdown_menu('oidc', 'Add OIDC Client', idps, 'oidcButton1', 'oidcMenu1')
    self.dropdown_menu('oauth2', 'Add OAuth2 Client', idps, 'oauth2Button1', 'oauth2Menu1')
    self.dropdown_menu('saml', 'Add SAML Client', idps, 'samlButton1', 'samlMenu1')
    self.dropdown_menu('cas', 'Add CAS Client', idps, 'casButton1', 'casMenu1')

    for idp_id in sorted(idps.keys()):
      
      idp = idps[idp_id]
      
      idp_id_to_open = self.get_query_string_param('idpid', '')
      opened = bool(idp_id == idp_id_to_open)

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
                <span onclick="this.querySelector('.confirm').style.display='inline'; this.querySelector('.initial').style.display='none';">
                  <span class="initial">
                    <span class="smallbutton">
                    Remove IdP
                    </span>
                  </span>
                  <span class="confirm" style="display:none;">
                    Confirm removal?
                      <a href="/client/idp/admin/remove?idpid={idp_id}" class="smallButton">Yes</a>
                      <a href="/" class="smallButton">No</a>
                  </span>
                </span>
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
      self.oidc_client_idp_menu(idp, idp_id)

      # clients OAuth 2
      self.oauth2_client_idp_menu(idp, idp_id)

      # SP SAML
      self.saml_client_idp_menu(idp, idp_id)

      # clients CAS
      self.cas_client_idp_menu(idp, idp_id)

      self.add_html("""
              </div>
            </span>
          </span>
        </div>
        """)
      
  def oidc_client_button(self):
    self.add_middle_button("Add OIDC Client", "/client/oidc/admin/modifyclient")

  def oauth2_client_button(self):
    self.add_middle_menu("Add OAuth 2 Client", {
      "Confidential OAuth 2.1 client": "/client/oauth2/admin/modifyclient?clienttype=confidential_21",
      "Public OAuth 2.1 client": "/client/oauth2/admin/modifyclient?clienttype=public_21",
      "Confidential OAuth 2.0 client": "/client/oauth2/admin/modifyclient?clienttype=confidential_20",
      "Public OAuth 2.0 client": "/client/oauth2/admin/modifyclient?clienttype=public_20"
      }
    )
  
  def saml_client_button(self):
    if self.hreq.saml_prerequisite:
      self.add_middle_button("Add SAML SP", "/client/saml/admin/modifyclient")

  def cas_client_button(self):
    self.add_middle_button("Add CAS Client", "/client/cas/admin/modifyclient")
  
  def oidc_client_idp_menu(self, idp, idp_id) :
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
  
  def oauth2_client_idp_menu(self, idp, idp_id) :
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
  
  def saml_client_idp_menu(self, idp, idp_id) :
    if self.hreq.saml_prerequisite and idp.get('saml_clients'):
      self.add_html("""<div style="font-size: 14px">SAML SP</div>""")          
      
      for client_id in sorted(idp['saml_clients'].keys()):
        client = idp['saml_clients'][client_id]
        self.add_html("""
          <div style="font-size: 14px; margin-left: 20px;">
            <span>{name}</span>
            <span><a href="/client/saml/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
            <span><a href="/client/saml/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Config</a></span>
          </div>
          """.format(
            name = html.escape(client.get('name', 'SP')),
            idp_id = urllib.parse.quote_plus(idp_id),
            app_id = urllib.parse.quote_plus(client_id),
          )
        )
  
  def cas_client_idp_menu(self, idp, idp_id) :
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
  
  def dropdown_menu(self, button_type, button_label, idps, button_id, menu_id):
    # START BUTTON
    self.start_dropdown(button_label, button_id, menu_id)

    if button_type != 'oauth2':
      self.new_idp_dropdown(button_type)
      self.existing_idp_dropdown(button_type, idps)
    else :
      self.new_idp_dropdown_complex()
      self.existing_idp_dropdown_complex(idps)

    # END BUTTON
    self.end_dropdown(button_id, menu_id)
  
  def start_dropdown(self, button_label, button_ID, menu_ID) :
    self.add_html("""
      <div class="dd-root" id="{button_id}">
        <div class="dd-btn">
          {button_label}
        </div>
    <div class="menu" id="{menu_id}">
    """.format(
      button_id = button_ID,
      button_label = button_label,
      menu_id = menu_ID)
    )
  
  def new_idp_dropdown(self, client_type) :
    end_link = "/client/" + client_type + "/admin/modifyclient"

    self.add_html("""
    <a class="end-link" href="{end_link}">
      <div class="menu-item">
      With new IdP
      </div>
    </a>
    """.format(end_link= end_link))
  
  # Only for OAuth
  def new_idp_dropdown_complex(self) :

    self.add_html("""
    <div class="menu-item">
        New IdP
        <div class="sub">
          <a class="end-link" href="/client/oauth2/admin/modifyclient?clienttype=confidential_21"><div class="menu-item">Confidential OAuth 2.1 client</div></a>
          <a class="end-link" href="/client/oauth2/admin/modifyclient?clienttype=public_21"><div class="menu-item">Public OAuth 2.1 client</div></a>
          <a class="end-link" href="/client/oauth2/admin/modifyclient?clienttype=confidential_20"><div class="menu-item">Confidential OAuth 2.0 client</div></a>
          <a class="end-link" href="/client/oauth2/admin/modifyclient?clienttype=public_20"><div class="menu-item">Public OAuth 2.0 client</div></a>
        </div>
      </div>
    """)
  
  def existing_idp_dropdown(self, client_type, idps) :
    self.add_html("""
    <div class="menu-item">
      With existing IdP
        <div class="sub">""")
    
    for idp_id in sorted(idps.keys()):
      idp = idps[idp_id]
      idp_name = idp.get('name', 'IDP')
      end_link = "/client/" + client_type + "/admin/modifyclient?idp_id=" + idp_id

      self.add_html("""
        <a class="end-link" href="{end_link}">
          <div class="menu-item">
          {idp_name}
          </div>
	      </a>
        """.format(
          end_link = end_link,
          idp_name = html.escape(idp_name))
      )
                  
    self.add_html("""
        </div>
    </div>
    """)
  
  # Only for OAuth
  def existing_idp_dropdown_complex(self, idps) :
    self.add_html("""
    <div class="menu-item">
      With existing IdP
        <div class="sub">""")
    
    for idp_id in sorted(idps.keys()):
      idp = idps[idp_id]
      idp_name = idp.get('name', 'IDP')

      self.add_html("""
        <div class="menu-item">
          {idp_name}
          <div class="sub2">
            <a class="end-link" href="/client/oauth2/admin/modifyclient?idp_id={idp_id}&clienttype=confidential_21"><div class="menu-item">Confidential OAuth 2.1 client</div></a>
            <a class="end-link" href="/client/oauth2/admin/modifyclient?idp_id={idp_id}&clienttype=public_21"><div class="menu-item">Public OAuth 2.1 client</div></a>
            <a class="end-link" href="/client/oauth2/admin/modifyclient?idp_id={idp_id}&clienttype=confidential_20"><div class="menu-item">Confidential OAuth 2.0 client</div></a>
            <a class="end-link" href="/client/oauth2/admin/modifyclient?idp_id={idp_id}&clienttype=public_20"><div class="menu-item">Public OAuth 2.0 client</div></a>
          </div>
        </div>
        """.format(
          idp_id = urllib.parse.quote_plus(idp_id),
          idp_name = html.escape(idp_name))
      )
                  
    self.add_html("""
        </div>
    </div>
    """)

  def end_dropdown(self, button_ID, menu_ID) :
    self.add_html("""
    </div>
    </div>
    """)
    self.add_javascript("""display_dropdown_menu(\'{button_id}\',\'{menu_id}\')""".format(button_id=button_ID, menu_id=menu_ID))