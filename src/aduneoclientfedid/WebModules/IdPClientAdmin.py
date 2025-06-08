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
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import CfiForm
from ..Configuration import Configuration
from .CASClientAdmin import CASClientAdmin
from .OIDCClientAdmin import OIDCClientAdmin
from .OAuthClientAdmin import OAuthClientAdmin
import copy
import html
import uuid

try:
  from .SAMLClientAdmin import SAMLClientAdmin
except:
  pass


@register_web_module('/client/idp/admin')
class IdPClientAdmin(BaseHandler):

  @register_page_url(url='modify', method='GET', template='page_default.html', continuous=False)
  def modify_display(self):
    """ Modification des paramètres de l'IdP
    
    Remarque : on peut aussi modifier ces paramètres dans les pages d'adminisration OIDC et OAuth si l'IdP n'a qu'un unique client
    
    Versions:
      25/12/2024 (mpham) version initiale
      09/01/2025 (mpham) include Javascript pour SAML
    """


    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {'oidc': {}, 'oauth2': {}}}
    else:
      idp = copy.deepcopy(self.conf['idps'][idp_id])

    idp['id'] = idp_id
    form = self.get_idp_form(idp)  

    self.add_javascript_include('/javascript/SAMLClientAdmin.js')
    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())


  @register_url(url='modify', method='POST')
  def modify_save(self):
    """ Crée ou modifie un IdP dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      25/12/2024 (mpham)
      31/12/2024 (mpham) les identifiants des IdP sont maintenant préfixés (idp_<idp_id>)
      09/01/2025 (mpham) paramètres SAML
      23/01/2025 (mpham) prise en compte des paramètres SAML uniquement si saml_prerequisite vérifié
      28/01/2025 (mpham) paramètres CAS
      31/01/2025 (mpham) SAML : si l'entity ID n'est pas donnée, on n'enregistre pas les bindings (ça permet de conserver saml à {})
      03/06/2025 (mpham) DNS override for OAuth 2 token endpoint
      08/06/2025 (mpham) DNS override for all OIDC and OAuth 2 endpoints
    """
    
    idp_id = self.post_form['idp_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      self.conf['idps'][idp_id] = {'idp_parameters': {'oidc': {}, 'oauth2': {}, 'saml': {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    oidc_params = idp_params.get('oidc')
    saml_params = idp_params.get('saml')
    cas_params = idp_params.get('cas')
    if not oidc_params:
      idp['idp_parameters']['oidc'] = {}
      oidc_params = idp_params['oidc']
    oauth2_params = idp_params.get('oauth2')
    if not oauth2_params:
      idp_params['oauth2'] = {}
      oauth2_params = idp_params['oauth2']
    if not saml_params:
      idp_params['saml'] = {}
      saml_params = idp_params['saml']
    if not cas_params:
      idp_params['cas'] = {}
      cas_params = idp_params['cas']
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name'].strip()

    # Paramètres OIDC
    for item in ['endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'userinfo_method', 'signature_key_configuration', 'jwks_uri', 'signature_key',
    'token_endpoint_dns_override', 'userinfo_endpoint_dns_override']:
      if self.post_form.get('oidc_'+item, '') == '':
        oidc_params.pop(item, None)
      else:
        oidc_params[item] = self.post_form['oidc_'+item].strip()
      
    # Paramètres OAuth 2
    for item in ['endpoint_configuration', 'metadata_uri', 'authorization_endpoint', 'token_endpoint', 
    'revocation_endpoint', 'introspection_endpoint', 'introspection_http_method', 'introspection_auth_method', 'signature_key_configuration', 'jwks_uri', 'signature_key',
    'token_endpoint_dns_override', 'introspection_endpoint_dns_override', 'revocation_endpoint_dns_override']:
      if self.post_form.get('oauth2_'+item, '') == '':
        oauth2_params.pop(item, None)
      else:
        oauth2_params[item] = self.post_form['oauth2_'+item].strip()
      
    # Paramètres SAML
    if self.hreq.saml_prerequisite:
      for item in ['idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_certificate']:
        if self.post_form.get(item, '') == '':
          saml_params.pop(item, None)
        else:
          saml_params[item] = self.post_form[item].strip()
      
      if saml_params.get('idp_entity_id'):
        for item in ['idp_authentication_binding_capabilities', 'idp_logout_binding_capabilities']:
          if self.post_form.get(item, '') == '':
            saml_params.pop(item, None)
          else:
            saml_params[item] = self.post_form[item].split('\t')
        
    # Paramètres CAS
    for item in ['cas_server_url']:
      if self.post_form.get('cas_'+item, '') == '':
        cas_params.pop(item, None)
      else:
        cas_params[item] = self.post_form['cas_'+item].strip()
      
    # Paramètres communs
    for item in ['verify_certificates']:
      if item in self.post_form:
        idp_params[item] = 'on'
      else:
        idp_params[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/idp/admin/display?idpid={html.escape(idp_id)}")


  @register_page_url(url='display', method='GET', template='page_default.html', continuous=False)
  def display(self):
    """ Affichage des paramètres de l'IdP
    
    Versions:
      25/12/2024 (mpham) version initiale
      03/01/2025 (mpham) SAML SP
      28/01/2025 (mpham) clients CAS
      31/01/2025 (mpham) on appelle uniquement modifyclient et plus modifymulti
    """


    idp_id = self.get_query_string_param('idpid', '')
    idp = copy.deepcopy(self.conf['idps'][idp_id])
    
    idp['id'] = idp_id
    form = self.get_idp_form(idp, display_only=True)  

    self.add_html(form.get_html(display_only=True))

    # Boutons de modification de l'IdP
    self.add_html(f""" 
      <div>
        <span><a href="modify?idpid={idp_id}" class="smallbutton">Modify IdP parameters</a></span>
        <span><a href="remove?idpid={idp_id}" class="smallbutton">Remove IdP</a></span>
      </div>
    """)
    
    # Clients OIDC
    self.add_html(f""" 
      <h2>OpenID Connect clients</h2>
      <div>
        <span><a href="/client/oidc/admin/modifyclient?idpid={idp_id}" class="smallbutton">Add client</a></span>
      </div>
    """)
    
    for client_id in idp.get('oidc_clients', {}):
      client = idp['oidc_clients'][client_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oidc/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
          <span><a href="/client/oidc/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Logout</a></span>
          <span><a href="/client/oidc/admin/removeapp?idpid={idp_id}&appid={app_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(client.get('name', '')),
          idp_id = idp_id,
          app_id = client_id,
          div_id = param_uuid,
          ))
          
      client['idp_id'] = idp_id
      client['app_id'] = client_id
      client_form = OIDCClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = client_form.get_html(display_only=True),
          ))
    
    # Clients OAuth 2
    self.add_html(f""" 
      <h2>OAuth 2 clients</h2>
      <div>
        <span><a href="/client/oauth2/admin/modifyclient?idpid={idp_id}" class="smallbutton">Add client</a></span>
      </div>
    """)
    
    for client_id in idp.get('oauth2_clients', {}):
      client = idp['oauth2_clients'][client_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oauth2/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oauth2/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
          <span><a href="/client/oauth2/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Revoke</a></span>
          <span><a href="/client/oauth2/admin/removeapp?idpid={idp_id}&appid={app_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(client.get('name', '')),
          idp_id = idp_id,
          app_id = client_id,
          div_id = param_uuid,
          ))
          
      client['idp_id'] = idp_id
      client['app_id'] = client_id
      client_form = OAuthClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = client_form.get_html(display_only=True),
          ))

    # API OAuth 2
    self.add_html(f""" 
      <h2>OAuth 2 API</h2>
      <div>
        <span><a href="/client/oauth2/admin/modifyapi?idpid={idp_id}" class="smallbutton">Add API</a></span>
      </div>
    """)
    
    for api_id in idp.get('oauth2_apis', {}):
      api = idp['oauth2_apis'][api_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/oauth2/admin/modifyapi?idpid={idp_id}&apiid={api_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/oauth2/admin/removeapi?idpid={idp_id}&apiid={api_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(api.get('name', '')),
          idp_id = idp_id,
          api_id = api_id,
          div_id = param_uuid,
          ))
          
      api['idp_id'] = idp_id
      api['api_id'] = api_id
      api_form = OAuthClientAdmin.get_api_form(self, api)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = api_form.get_html(display_only=True),
          ))

    # SAML SP
    if self.hreq.saml_prerequisite:

      self.add_html(f""" 
        <h2>SAML service providers (SP)</h2>
        <div>
          <span><a href="/client/saml/admin/modifyclient?idpid={idp_id}" class="smallbutton">Add SAML SP</a></span>
        </div>
      """)
    
      for sp_id in idp.get('saml_clients', {}):
        sp = idp['saml_clients'][sp_id]
        param_uuid = str(uuid.uuid4())
        self.add_html("""
          <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
            <span style="flex-grow: 1; font-size: 12px;">{name}</span>
            <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
            <span><a href="/client/saml/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
            <span><a href="/client/saml/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
            <span><a href="/client/saml/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Logout</a></span>
            <span><a href="/client/saml/admin/removeapp?idpid={idp_id}&appid={app_id}" class="smallbutton">Remove</a></span>
          </div>
          """.format(
            name = html.escape(sp.get('name', '')),
            idp_id = idp_id,
            app_id = sp_id,
            div_id = param_uuid,
            ))
            
        sp['idp_id'] = idp_id
        sp['app_id'] = sp_id
        sp_form = SAMLClientAdmin.get_app_form(self, sp)
            
        self.add_html("""
          <div id="panel_{div_id}" style="display: none;">{form}</div>
          """.format(
            div_id = param_uuid,
            form = sp_form.get_html(display_only=True),
            ))
    
    # Clients CAS
    self.add_html(f""" 
      <h2>CAS clients</h2>
      <div>
        <span><a href="/client/cas/admin/modifyclient?idpid={idp_id}" class="smallbutton">Add client</a></span>
      </div>
    """)
    
    for client_id in idp.get('cas_clients', {}):
      client = idp['cas_clients'][client_id]
      param_uuid = str(uuid.uuid4())
      self.add_html("""
        <div style="width: 1140px; display: flex; align-items: center; background-color: #fbe1686b; padding: 3px 3px 3px 6px; margin-top: 2px; margin-bottom: 2px;">
          <span style="flex-grow: 1; font-size: 12px;">{name}</span>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide parameters" displayLabel="Display parameters">Display parameters</span>
          <span><a href="/client/cas/admin/modifyclient?idpid={idp_id}&appid={app_id}" class="smallbutton">Modify</a></span>
          <span><a href="/client/cas/login/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Login</a></span>
          <span><a href="/client/cas/logout/preparerequest?idpid={idp_id}&appid={app_id}" class="smallbutton">Logout</a></span>
          <span><a href="/client/cas/admin/removeapp?idpid={idp_id}&appid={app_id}" class="smallbutton">Remove</a></span>
        </div>
        """.format(
          name = html.escape(client.get('name', '')),
          idp_id = idp_id,
          app_id = client_id,
          div_id = param_uuid,
          ))
          
      client['idp_id'] = idp_id
      client['app_id'] = client_id
      client_form = CASClientAdmin.get_app_form(self, client)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = param_uuid,
          form = client_form.get_html(display_only=True),
          ))


  @register_page_url(url='remove', method='GET', template='page_default.html', continuous=False)
  def remove_idp_display(self):
    """ Page de suppression d'un IdP
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      
      # Affichage de l'IdP
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
      idp_form.set_title('Remove IdP'+(' '+idp['name'] if idp.get('name') else ''))
      idp_form.add_button('Remove', f'removeconfirmed?idpid={idp_id}', display='all')
      idp_form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')

      self.add_html(idp_form.get_html(display_only=True))
      self.add_javascript(idp_form.get_javascript())

    except AduneoError as e:
      self.add_html(f"""
        <div>
          Error: {e}
        </div>
        <div>
          <span><a class="smallbutton" href="{e.action}">{e.button_label}</a></span>
        </div>
        """)


  @register_url(url='removeconfirmed', method='GET')
  def remove_idp_remove(self):
    """
    Supprime un IdP
    
    29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", action="/")
      
      del self.conf['idps'][idp_id]
      Configuration.write_configuration(self.conf)
      self.send_redirection("/")
      
    except AduneoError as e:
      self.send_redirection(e.action)


  def get_idp_form(handler, idp:dict, display_only:bool=False):
    """ Retourne un RequesterForm avec un IdP
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      idp: dict avec les paramètres de l'IdP, dans le formalisme du fichier de configuration
             Attention : il faut ajouter le champ id avec l'identifiant unique de l'IdP
      display_only: adapte le formulaire en fonction du mode, attention, il faut toujours passer le bon display_only à CfiForm.get_html
             
    Returns:
      objet RequesterForm
    
    Versions:
      25/12/2024 (mpham) version initiale
      09/01/2025 (mpham) paramètres SAML
      23/01/2025 (mpham) les paramètres SAML ne sont affichés que si saml_prerequisite est bien vérifié
      28/01/2025 (mpham) paramètres SAML
      31/01/2025 (mpham) en lecture seule, l'affiche pas les INPUT des sections non définies
      31/01/2025 (mpham) option same_as pour la configuration des endpoints OIDC et OAuth 2
      03/06/2025 (mpham) DNS override for OAuth 2 token endpoint
      08/06/2025 (mpham) DNS override for all OIDC and OAuth 2 endpoints
    """

    idp_params = idp['idp_parameters']
    oidc_params = idp_params.get('oidc', {})
    oauth2_params = idp_params.get('oauth2', {})
    saml_params = idp_params.get('saml', {})
    cas_params = idp_params.get('cas', {})

    # possibilités de SAML en binding
    idp_authentication_binding_capabilities = saml_params.get('idp_authentication_binding_capabilities')
    if not idp_authentication_binding_capabilities:
      idp_authentication_binding_capabilities = handler.conf.get('/default/saml/idp_authentication_binding_capabilities')
      if not idp_authentication_binding_capabilities:
        idp_authentication_binding_capabilities = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']

    idp_logout_binding_capabilities = saml_params.get('idp_logout_binding_capabilities')
    if not idp_logout_binding_capabilities:
      idp_logout_binding_capabilities = handler.conf.get('/default/saml/idp_logout_binding_capabilities')
      if not idp_logout_binding_capabilities:
        idp_logout_binding_capabilities = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']
        
    form_content = {
      'idp_id': idp.get('id', ''),
      'name': idp.get('name', ''),
      'oidc_endpoint_configuration': oidc_params.get('endpoint_configuration', 'discovery_uri'),
      'oidc_discovery_uri': oidc_params.get('discovery_uri', ''),
      'oidc_authorization_endpoint': oidc_params.get('', ''),
      'oidc_token_endpoint': oidc_params.get('', ''),
      'oidc_userinfo_endpoint': oidc_params.get('userinfo_endpoint', ''),
      'oidc_userinfo_method': oidc_params.get('userinfo_method', 'get'),
      'oidc_logout_endpoint': oidc_params.get('logout_endpoint', ''),
      'oidc_issuer': oidc_params.get('issuer', ''),
      'oidc_signature_key_configuration': oidc_params.get('signature_key_configuration', 'discovery_uri'),
      'oidc_jwks_uri': oidc_params.get('jwks_uri', ''),
      'oidc_signature_key': oidc_params.get('signature_key', ''),
      'oidc_token_endpoint_dns_override': oidc_params.get('token_endpoint_dns_override', ''),
      'oidc_userinfo_endpoint_dns_override': oidc_params.get('userinfo_endpoint_dns_override', ''),
      'oauth2_endpoint_configuration': oauth2_params.get('endpoint_configuration', 'metadata_uri'),
      'oauth2_metadata_uri': oauth2_params.get('metadata_uri', ''),
      'oauth2_authorization_endpoint': oauth2_params.get('', ''),
      'oauth2_token_endpoint': oauth2_params.get('', ''),
      'oauth2_introspection_endpoint': oauth2_params.get('introspection_endpoint', ''),
      'oauth2_introspection_http_method': oauth2_params.get('introspection_http_method', 'get'),
      'oauth2_introspection_auth_method': oauth2_params.get('introspection_auth_method', 'basic'),
      'oauth2_revocation_endpoint': oauth2_params.get('revocation_endpoint', ''),
      'oauth2_signature_key_configuration': oauth2_params.get('signature_key_configuration', 'jwks_uri'),
      'oauth2_jwks_uri': oauth2_params.get('jwks_uri', ''),
      'oauth2_signature_key': oauth2_params.get('signature_key', ''),
      'oauth2_token_endpoint_dns_override': oauth2_params.get('token_endpoint_dns_override', ''),
      'oauth2_introspection_endpoint_dns_override': oauth2_params.get('introspection_endpoint_dns_override', ''),
      'oauth2_revocation_endpoint_dns_override': oauth2_params.get('revocation_endpoint_dns_override', ''),
      'idp_entity_id': saml_params.get('idp_entity_id', ''),
      'idp_sso_url': saml_params.get('idp_sso_url', ''),
      'idp_slo_url': saml_params.get('idp_slo_url', ''),
      'idp_certificate': saml_params.get('idp_certificate', ''),
      'idp_authentication_binding_capabilities': '\t'.join(idp_authentication_binding_capabilities),
      'idp_logout_binding_capabilities': '\t'.join(idp_logout_binding_capabilities),
      'cas_cas_server_url': cas_params.get('cas_server_url', ''),
      'verify_certificates': Configuration.is_on(idp_params.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('idpadmin', form_content, action='modify', submit_label='Save') \
      .hidden('idp_id') \
      .text('name', label='Name') \
      .start_section('oidc_configuration', title="OIDC configuration", collapsible=True) 
    if oidc_params == {} and display_only:
      form.raw_html("OpenID Connect not configured")
    else:
      form \
        .start_section('op_endpoints', title="OP endpoints") \
          .closed_list('oidc_endpoint_configuration', label='Endpoint configuration', 
            values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration', 'same_as_oauth2': 'Same as OAuth 2'},
            default = 'discovery_uri'
            ) \
          .text('oidc_discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[oidc_endpoint_configuration] = 'discovery_uri'") \
          .text('oidc_authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .text('oidc_userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oidc_userinfo_method', label='Userinfo Request Method',
            values = {'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
        .end_section() \
        .start_section('id_token_validation', title="ID token validation") \
          .text('oidc_issuer', label='Issuer', clipboard_category='issuer', displayed_when="@[oidc_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oidc_signature_key_configuration', label='Signature key configuration',
            values = {'discovery_uri': 'JWKS from discovery URI', 'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
            default = 'discovery_uri'
            ) \
          .text('oidc_jwks_uri', label='JWKS URI', displayed_when="@[oidc_signature_key_configuration] = 'jwks_uri'") \
          .text('oidc_signature_key', label='Signature key', displayed_when="@[oidc_signature_key_configuration] = 'local_configuration'") \
        .end_section() \
        .start_section('oidc_clientfedid', title="OIDC ClientFedID configuration", collapsible=True, collapsible_default=True) \
          .text('oidc_token_endpoint_dns_override', label='Token endpoint DNS override', clipboard_category='token_endpoint_dns_override') \
          .text('oidc_userinfo_endpoint_dns_override', label='Userinfo endpoint DNS override', clipboard_category='userinfo_endpoint_dns_override') \
        .end_section() 
    form \
      .end_section() \
      .start_section('oauth2_configuration', title="OAuth 2 configuration", collapsible=True) 
    if oauth2_params == {} and display_only:
      form.raw_html("OAuth 2 not configured")
    else:
      form \
        .start_section('as_endpoints', title="Authorization Server Endpoints") \
          .closed_list('oauth2_endpoint_configuration', label='Endpoint configuration', 
            values={'metadata_uri': 'Authorization Server Metadata URI', 'local_configuration': 'Local configuration', 'same_as_oidc': 'Same as OIDC'},
            default = 'metadata_uri'
            ) \
          .text('oauth2_metadata_uri', label='AS Metadata URI', clipboard_category='metadata_uri', displayed_when="@[oauth2_endpoint_configuration] = 'metadata_uri'") \
          .text('oauth2_authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .text('oauth2_token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .text('oauth2_introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
          .closed_list('oauth2_introspection_http_method', label='Introspect. Request Method',
            values = {'get': 'GET', 'post': 'POST'},
            default = 'get'
            ) \
          .closed_list('oauth2_introspection_auth_method', label='Introspect. Authn. Scheme',
            values = {'none': 'None', 'basic': 'Basic', 'bearer_token': 'Bearer Token'},
            default = 'basic'
            ) \
          .text('oauth2_revocation_endpoint', label='Revocation endpoint', clipboard_category='revocation_endpoint', displayed_when="@[oauth2_endpoint_configuration] = 'local_configuration'") \
        .end_section() \
        .start_section('oauth2_clientfedid', title="OAuth 2 ClientFedID configuration", collapsible=True, collapsible_default=True) \
          .text('oauth2_token_endpoint_dns_override', label='Token endpoint DNS override', clipboard_category='token_endpoint_dns_override') \
          .text('oauth2_introspection_endpoint_dns_override', label='Introspection endpoint DNS override', clipboard_category='introspection_endpoint_dns_override') \
          .text('oauth2_revocation_endpoint_dns_override', label='Revocation endpoint DNS override', clipboard_category='revocation_endpoint_dns_override') \
        .end_section() 
    form \
      .end_section() \
      
    if handler.hreq.saml_prerequisite:
      form \
      .start_section('saml_configuration', title="SAML configuration", collapsible=True) 
      if saml_params == {} and display_only:
        form.raw_html("SAML not configured")
      else:
        form \
        .upload_button('upload_idp_metadata', label='Upload IdP metadata', on_upload="parseIdPMetadata(upload_content, cfiForm);") \
        .text('idp_entity_id', label='IdP entity ID', clipboard_category='idp_entity_id') \
        .text('idp_sso_url', label='IdP SSO URL', clipboard_category='idp_sso_url') \
        .text('idp_slo_url', label='IdP SLO URL', clipboard_category='idp_slo_url') \
        .textarea('idp_certificate', label='IdP certificate', rows=10, clipboard_category='idp_certificate', upload_button='Upload IdP certificate') \
        .hidden('idp_authentication_binding_capabilities') \
        .hidden('idp_logout_binding_capabilities') 
      form \
      .end_section() \
      
    form \
      .start_section('cas_configuration', title="CAS configuration", collapsible=True) 
    if cas_params == {} and display_only:
      form.raw_html("CAS not configured")
    else:
      form \
        .text('cas_cas_server_url', label='CAS server URL', clipboard_category='cas_server_url') 
    form \
      .end_section() \
      .start_section('common_configuration', title="Common configuration", collapsible=True) \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('IdP Configuration'+('' if form_content['name'] == '' else ': '+form_content['name']))
    if idp.get('id', '') == '':
      form.add_button('Cancel', '/', display='modify')
    else:
      form.add_button('Cancel', f"display?idpid={idp['id']}", display='modify')
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form
