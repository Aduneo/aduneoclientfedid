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
from ..CryptoTools import CryptoTools

import copy
import datetime
import html
import lxml
import lxml.builder
import os


@register_web_module('/client/saml/admin')
class SAMLClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=True)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application : modify_single
        - modification différencée IdP et les différents clients qu'il gère       : modify_multi
        
    Versions:
      01/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """

    idp = {}

    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création
      self.modify_single_display()
    else:
      # Modification
      idp = self.conf['idps'].get(idp_id)
      if not idp:
        raise AduneoError(f"IdP {idp_id} not found in configuration")
        
      oidc_clients = idp.get('oidc_clients', {})  
      oauth2_clients = idp.get('oauth2_clients', {})  
      saml_clients = idp.get('saml_clients', {})  
        
      if len(oidc_clients) == 0 and len(oauth2_clients) == 0 and len(saml_clients) == 1:
        self.modify_single_display()
      else:
        self.modify_multi_display()
      

  def modify_single_display(self):
    """ Modification des paramètres de l'IdP et du client sur la même page
    
    Versions:
      01/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      app_id = 'sp'
      idp = {'idp_parameters': {'saml': {}}, 'saml_clients': {app_id: {}}}
    if idp_id != '' and app_id != '':
      idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    saml_params = idp_params['saml']
    app_params = idp['saml_clients'][app_id]

    form_content = {
      'idp_id': idp_id,
      'app_id': app_id,
      'name': idp.get('name', ''),
      'idp_entity_id': saml_params.get('idp_entity_id', ''),
      'idp_sso_url': saml_params.get('idp_sso_url', ''),
      'idp_slo_url': saml_params.get('idp_slo_url', ''),
      'idp_certificate': saml_params.get('idp_certificate', ''),
      'sp_entity_id': app_params.get('sp_entity_id', ''),
      'sp_acs_url': app_params.get('sp_acs_url', ''),
      'sp_slo_url': app_params.get('sp_slo_url', ''),
      'sp_key_configuration': app_params.get('sp_key_configuration', 'clientfedid_keys'),
      'sp_private_key': app_params.get('sp_private_key', ''),
      'sp_certificate': app_params.get('sp_certificate', self._get_clientfedid_certificate()),
      'nameid_policy': app_params.get('nameid_policy', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'),
      'authentication_binding': app_params.get('authentication_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_auth_request': Configuration.is_on(app_params.get('sign_auth_request', 'off')),
      'logout_binding': app_params.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_logout_request': Configuration.is_on(app_params.get('sign_logout_request', 'off')),
      }
    
    form = CfiForm('samladminsingle', form_content, action='modifyclientsingle', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('idp_parameters', title="IdP parameters") \
        .upload_button('upload_idp_metadata', label='Upload IdP metadata', on_upload="parseIdPMetadata(upload_content, cfiForm);") \
        .text('idp_entity_id', label='IdP entity ID', clipboard_category='idp_entity_id') \
        .text('idp_sso_url', label='IdP SSO URL', clipboard_category='idp_sso_url') \
        .text('idp_slo_url', label='IdP SLO URL', clipboard_category='idp_slo_url') \
        .textarea('idp_certificate', label='IdP certificate', rows=10, clipboard_category='idp_certificate', upload_button='Upload IdP certificate') \
      .end_section() \
      .start_section('sp_parameters', title="SP parameters") \
        .button('download_sp_metadata', label='Download SP metadata', on_click='downloadSPMetadata(cfiForm)') \
        .text('sp_entity_id', label='SP entity ID', clipboard_category='sp_entity_id',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue('https://aduneo.com/FedTest/SAML'); }" 
          ) \
        .text('sp_acs_url', label='SP Assertion Consumer Service URL', clipboard_category='sp_acs_url',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/saml/login/acs'); }" 
          ) \
        .text('sp_slo_url', label='SP Single Logout URL', clipboard_category='sp_slo_url',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/saml/login/logout/callback'); }" 
          ) \
        .closed_list('sp_key_configuration', label='SP key configuration', 
          values = {'clientfedid_keys': 'ClientFedID keys', 'specific_keys': 'Specific keys'},
          default = 'clientfedid_keys'
          ) \
        .button('download_sp_cfi_certificate', label='Download ClientFedID certificate', link='/client/saml/admin/downloadcficertificate', displayed_when="@[sp_key_configuration] = 'clientfedid_keys'") \
        .button('generate_sp_keys', label='Generate SP keys', on_click='generateSPKeys(cfiForm)', displayed_when="@[sp_key_configuration] = 'specific_keys'") \
        .textarea('sp_private_key', label='SP private key', rows=10, clipboard_category='sp_private_key', upload_button='Upload SP private key', displayed_when="@[sp_key_configuration] = 'specific_keys'") \
        .textarea('sp_certificate', label='SP certificate', rows=10, clipboard_category='sp_certificate', upload_button='Upload SP certificate', displayed_when="@[sp_key_configuration] = 'specific_keys'") \
        .button('download_sp_specific_certificate', label='Download specific certificate', on_click='downloadSpecificCertificate(cfiForm)', displayed_when="@[sp_key_configuration] = 'specific_keys'") \
      .end_section() \
      .start_section('flow_parameters', title="Flow parameters") \
        .open_list('nameid_policy', label='NameID policy', clipboard_category='nameid_policy', 
          hints = [
            'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
            'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
            'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
            ]) \
        .closed_list('authentication_binding', label='Authentication binding', 
          values = {'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},
          default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          ) \
        .check_box('sign_auth_request', label='Sign authentication request') \
        .closed_list('logout_binding', label='Logout binding', 
          values = {'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},
          default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          ) \
        .check_box('sign_logout_request', label='Sign logout request') \
      .end_section() \
      
    form.set_title('SAML SP configuration'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', self.conf.is_on('/preferences/clipboard/remember_secrets', False))

    self.add_javascript_include('/javascript/SAMLClientAdmin.js')
    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    self.send_page()


  @register_url(url='modifyclientsingle', method='POST')
  def modify_single_modify(self):
    """ Crée ou modifie un IdP + SP SAML (mode single) dans la configuration
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      01/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création
      idp_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      app_id = f'saml_{idp_id[4:]}_sp'
      self.conf['idps'][idp_id] = {'idp_parameters': {'saml': {}}, 'saml_clients': {app_id: {}}}
    
    idp = self.conf['idps'][idp_id]
    idp_params = idp['idp_parameters']
    saml_params = idp_params['saml']
    app_params = idp['saml_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = idp_id

    idp['name'] = self.post_form['name'].strip()
    app_params['name'] = 'SAML SP'
    
    for item in ['idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_certificate']:
      if self.post_form.get(item, '') == '':
        saml_params.pop(item, None)
      else:
        saml_params[item] = self.post_form[item].strip()
      
    for item in ['sp_entity_id', 'sp_acs_url', 'sp_slo_url', 'sp_key_configuration', 'sp_private_key', 'sp_certificate', 'nameid_policy',
      'authentication_binding', 'logout_binding']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
    for item in ['sign_auth_request', 'sign_logout_request']:
      if item in self.post_form:
        app_params[item] = 'on'
      else:
        app_params[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/saml/login/preparerequest?idpid={idp_id}&appid={app_id}")


  @register_page_url(url='modifymulti', method='GET', template='page_default.html', continuous=True)
  def modify_multi_endpoint(self):
    self.modify_multi_display()

  
  def modify_multi_display(self):
    """ Modification des paramètres du client (mais pas de l'IdP)
    
    Versions:
      26/12/2024 (mpham) version initiale
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création de l'IdP, on redirige vers Single
      self.modify_single_display()
    else:
      idp = self.conf['idps'][idp_id]
      if app_id == '':
        # Création du client
        app_params = {}
      else:
        app_params = idp['oidc_clients'][app_id]
        
      # Affichage de l'IdP
      self.add_html(f"<h1>IdP {idp['name']}</h1>")
      idp_panel_uuid = str(uuid.uuid4())
      self.add_html("""
        <div>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
        </div>
        """.format(
          div_id = idp_panel_uuid,
          ))
          
      from .IdPClientAdmin import IdPClientAdmin
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = idp_panel_uuid,
          form = idp_form.get_html(display_only=True),
          ))

      app_params['idp_id'] = idp_id
      app_params['app_id'] = app_id
      app_form = self.get_app_form(app_params)

      self.add_html(app_form.get_html())
      self.add_javascript(app_form.get_javascript())
      
      self.send_page()


  @register_url(url='modifymulti', method='POST')
  def modify_multi_modify(self):
    """ Crée ou modifie une App OIDC pour un IdP existant (mode multi)
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      26/12/2024 (mpham) version initiale
      30/12/2024 (mpham) End session endpoint HTTP method
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (<idp_id>_oidc_) pour les rendre globalement uniques
    """
    
    idp_id = self.post_form['idp_id']
    idp = self.conf['idps'][idp_id]
    
    app_id = self.post_form['app_id']
    if app_id == '':
      # Création
      if not idp.get('oidc_clients'):
        idp['oidc_clients'] = {}
      
      app_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=idp['oidc_clients'].keys(), default='op', prefix=f'oidc_{idp_id[4:]}_')
      idp['oidc_clients'][app_id] = {}
    
    app_params = idp['oidc_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = app_id

    app_params['name'] = self.post_form['name'].strip()
    
    for item in ['redirect_uri', 'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'end_session_endpoint_method', 'post_logout_redirect_uri',
    'display', 'prompt', 'max_age', 'ui_locales', 'id_token_hint', 'login_hint', 'acr_values']:
      if self.post_form.get(item, '') == '':
        app_params.pop(item, None)
      else:
        app_params[item] = self.post_form[item].strip()
      
    for secret in ['client_secret']:
      if self.post_form.get(secret, '') != '':
        app_params[secret+'!'] = self.post_form[secret]
        
    Configuration.write_configuration(self.conf)
    
    self.send_redirection(f"/client/oidc/login/preparerequest?idpid={idp_id}&appid={app_id}")


  @register_url(url='downloadSPMetadata', method='POST')
  def download_sp_metadata(self):

    # métadonnées valables 10 ans
    expiration_date = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)).strftime('%Y-%m-%dT%H:%M:%SZ')

    certificate = "ERROR"
    if self.post_form['sp_key_configuration'] == 'Server keys':
      certificate_path = self.hreq.check_saml_certificate_exists()
      with open(certificate_path) as certificate_file:
        pem = certificate_file.read()
        pem_lines = pem.split('\n')
        certificate = ''.join(pem_lines[1:-2])
    else:
      certificate = self.post_form['sp_certificate']
    
    md = lxml.builder.ElementMaker(namespace="urn:oasis:names:tc:SAML:2.0:metadata", nsmap={'md' : "urn:oasis:names:tc:SAML:2.0:metadata"})
    ds = lxml.builder.ElementMaker(namespace="http://www.w3.org/2000/09/xmldsig#", nsmap={'ds' : "http://www.w3.org/2000/09/xmldsig#"})
    
    
    metadata = md.EntityDescriptor(
      md.SPSSODescriptor(
        md.KeyDescriptor(
          ds.KeyInfo(
            ds.X509Data(
              ds.X509Certificate(certificate)
            ),
          ),
        use = "signing"
        ),
        md.KeyDescriptor(
          ds.KeyInfo(
            ds.X509Data(
              ds.X509Certificate(certificate)
            ),
          ),
        use = "encryption"
        ),
        md.NameIDFormat(self.post_form['nameid_policy']),
        md.AssertionConsumerService(
          Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Location = self.post_form['sp_acs_url'],
          index="1"
        ),
        md.AssertionConsumerService(
          Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          Location = self.post_form['sp_acs_url'],
          index="2"
        ),
        md.SingleLogoutService ( 
          Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
          Location = self.post_form['sp_slo_url'], 
          index="1"
        ),
        md.SingleLogoutService ( 
          Binding = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          Location = self.post_form['sp_slo_url'], 
          index="2"
        ),
        AuthnRequestsSigned = self.post_form['sign_auth_request'],
        WantAssertionsSigned = "false",
        protocolSupportEnumeration = "urn:oasis:names:tc:SAML:2.0:protocol"
      ), 
      entityID = self.post_form['sp_entity_id'],
      validUntil = expiration_date
    )
  
    filename = self.post_form['filename']
    self.hreq.send_response(200)
    self.hreq.send_header('Content-type', 'text/xml')
    self.hreq.send_header('Content-disposition', 'attachment; filename='+filename+'.xml')
    self.hreq.end_headers()
    self.hreq.wfile.write(bytes('<?xml version="1.0"?>\n', "UTF-8"))
    self.hreq.wfile.write(lxml.etree.tostring(metadata, pretty_print=True))


  @register_page_url(url='removeapp', method='GET', template='page_default.html', continuous=True)
  def remove_app_display(self):
    """ Page de suppression d'un client OpenID Connect
    
    Versions:
      29/12/2024 (mpham) version initiale
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oidc_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OpenID Connect client {app_id} does not exist", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      
      # Affichage de l'IdP
      self.add_html(f"<h1>IdP {idp['name']}</h1>")
      idp_panel_uuid = str(uuid.uuid4())
      self.add_html("""
        <div>
          <span class="smallbutton" onclick="togglePanel(this, 'panel_{div_id}')" hideLabel="Hide IdP parameters" displayLabel="Display IdP parameters">Display IdP parameters</span>
        </div>
        """.format(
          div_id = idp_panel_uuid,
          ))
          
      from .IdPClientAdmin import IdPClientAdmin
      idp['id'] = idp_id
      idp_form = IdPClientAdmin.get_idp_form(self, idp)
          
      self.add_html("""
        <div id="panel_{div_id}" style="display: none;">{form}</div>
        """.format(
          div_id = idp_panel_uuid,
          form = idp_form.get_html(display_only=True),
          ))

      app_params['idp_id'] = idp_id
      app_params['app_id'] = app_id
      app_form = self.get_app_form(app_params)
      app_form.set_title('Remove Oauth 2 app '+(' '+app_params['name'] if app_params.get('name') else ''))
      app_form.add_button('Remove', f'removeappconfirmed?idpid={idp_id}&appid={app_id}', display='all')
      app_form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')

      self.add_html(app_form.get_html(display_only=True))
      self.add_javascript(app_form.get_javascript())
      
      self.send_page()

    except AduneoError as e:
      self.add_html(f"""
        <div>
          Error: {e}
        </div>
        <div>
          <span><a class="smallbutton" href="{e.action}">{e.button_label}</a></span>
        </div>
        """)


  @register_url(url='removeappconfirmed', method='GET')
  def remove_app_remove(self):
    """
    Supprime un client OpenID Connect
    
    28/12/2021 (mpham) version initiale
    29/12/2024 (mpham) suppression après page de confirmation
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", action="/")
      idp = self.conf['idps'][idp_id]
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['oidc_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"OpenID Connect client {app_id} does not exist", action=f"/client/idp/admin/display?idpid={idp_id}")

      del idp['oidc_clients'][app_id]
      Configuration.write_configuration(self.conf)
      self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")
      
    except AduneoError as e:
      self.send_redirection(e.action)


  def get_app_form(handler, app_params:dict):
    """ Retourne un RequesterForm avec un client OIDC (sans les paramètres de l'IdP)
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      app_params: dict avec les paramètres du client OIDC (RP), dans le formalisme du fichier de configuration
             Attention : il faut ajouter deux champs
              - idp_id avec l'identifiant unique de l'IdP
              - app_id avec l'identifiant unique du client
             
    Returns:
      objet RequesterForm
    
    Versions:
      26/12/2024 (mpham) version initiale adaptée de modify_single_display
      30/12/2024 (mpham) End session endpoint HTTP method
    """

    form_content = {
      'idp_id': app_params['idp_id'],
      'app_id': app_params['app_id'],
      'name': app_params.get('name', ''),
      'redirect_uri': app_params.get('redirect_uri', ''),
      'post_logout_redirect_uri': app_params.get('post_logout_redirect_uri', ''),
      'client_id': app_params.get('client_id', ''),
      'scope': app_params.get('scope', 'openid'),
      'response_type': app_params.get('response_type', 'code'),
      'token_endpoint_auth_method': app_params.get('token_endpoint_auth_method', 'client_secret_basic'),
      'end_session_endpoint_method': app_params.get('end_session_endpoint_method', 'post'),
      'display': app_params.get('display', ''),
      'prompt': app_params.get('prompt', ''),
      'max_age': app_params.get('max_age', ''),
      'ui_locales': app_params.get('ui_locales', ''),
      'id_token_hint': app_params.get('id_token_hint', ''),
      'login_hint': app_params.get('login_hint', ''),
      'acr_values': app_params.get('acr_values', ''),
      }
    
    form = CfiForm('oidcadminmulti', form_content, action='modifymulti', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
      .start_section('rp_endpoints', title="RP endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/login/callback'); }" 
          ) \
        .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri',
          on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/logout/callback'); }" \
          ) \
      .end_section() \
      .start_section('openid_connect_configuration', title="OpenID Connect Configuration") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope') \
        .closed_list('response_type', label='Reponse type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .closed_list('end_session_endpoint_method', label='End session endpoint HTTP method', 
          values={'get': 'GET', 'post': 'POST'},
          default = 'post'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() \
      .start_section('request_params', title="Request Parameters", collapsible=True, collapsible_default=True) \
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
      .end_section()
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form





  
  @register_url(url='modifyclientold', method='GET')
  def display(self):
    
    """
    Ajout/modification d'un client SAML
    
    mpham 06/03/20241
    """
    
    sp = {}
    sp_id = self.get_query_string_param('id', '')
    if sp_id == '':
      sp['sp_entity_id'] = 'https://aduneo.com/FedTest/SAML'
    else:
      sp = self.conf['saml_clients'][sp_id]

    self.add_content('<script src="/javascript/SAMLClientAdmin.js"></script>')
    self.add_content('<h2>SAML SP Configuration</h3>')
    
    self.add_content('<form name="sp" action="" method="post">')
    self.add_content('<input name="sp_id" value="'+html.escape(sp_id)+'" type="hidden" />')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>Name</td><td><input name="name" value="'+html.escape(sp.get('name', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('</table>')
    
    self.add_content('<h3>Parameters coming from the idP</h3>')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>&nbsp;</td><td><label for="upload_idp_metadata_input" class="middlebutton">Upload IdP Metadata</label><input id="upload_idp_metadata_input" type="file" style="display: none" onchange="uploadIdPMetadata(event)"></td></tr>')
    self.add_content('<tr><td>IdP Entity ID</td><td><input name="idp_entity_id" value="'+html.escape(sp.get('idp_entity_id', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>IdP SSO URL</td><td><input name="idp_sso_url" value="'+html.escape(sp.get('idp_sso_url', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>IdP SLO URL</td><td><input name="idp_slo_url" value="'+html.escape(sp.get('idp_slo_url', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>IdP Certificate</td><td><textarea name="idp_certificate" id="idp_certificate_input" rows="10" class="intable">'+html.escape(sp.get('idp_certificate', ''))+'</textarea>')
    self.add_content('  <label for="upload_idp_certificate_input" class="middlebutton">Upload certificate</label><input id="upload_idp_certificate_input" type="file" style="display: none" onchange="uploadPem(event)"/></td></tr>')
    self.add_content('</table>')
    
    self.add_content('<h3>Parameters to send to the idP</h3>')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td>&nbsp;</td><td><button type="button" class="middlebutton" onclick="downloadSPMetadata()">Download SP metadata</button></td></tr>')
    self.add_content('<tr><td>SP Entity ID</td><td><input name="sp_entity_id" value="'+html.escape(sp.get('sp_entity_id', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>SP Assertion Consumer Service URL</td><td><input name="sp_acs_url" value="'+html.escape(sp.get('sp_acs_url', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>SP Single Logout URL</td><td><input name="sp_slo_url" value="'+html.escape(sp.get('sp_slo_url', ''))+'" class="intable" type="text"></td></tr>')
    
    # configuration de la clé de vérification de signature
    self.add_content('<tr id="sp_key_configuration"><td>SP key configuration</td><td><select name="sp_key_configuration" class="intable" onchange="changeSPKeyConfiguration()">')
    for value in ('Server keys', 'Specific keys'):
      selected = ''
      if value.casefold() == sp.get('sp_key_configuration', 'Server keys').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select>')
    
    display_style = 'none'
    if sp.get('sp_key_configuration', 'Server keys').casefold() == 'specific keys':
      display_style = 'block'
    self.add_content('&nbsp;&nbsp;<button id="generate_keys" type="button" class="middlebutton" onclick="generateKeys()" style="display: '+display_style+'">Generate keys</button>')
    self.add_content('</td></tr>')

    display_style = 'none'
    if sp.get('sp_key_configuration', 'Server keys').casefold() == 'server keys':
      display_style = 'table-row'
    self.add_content('<tr id="sp_download_server_certificate" style="display: '+display_style+'"><td>Server certificate</td><td><a href="/downloadservercertificate"><button type="button" class="middlebutton">Download certificate</button></a></td></tr>')

    display_style = 'none'
    if sp.get('sp_key_configuration', 'Server keys').casefold() == 'specific keys':
      display_style = 'table-row'
    self.add_content('<tr id="sp_private_key" style="display: '+display_style+'"><td>SP private key</td><td><textarea name="sp_private_key" id="sp_private_key_input" rows="10" class="intable">'+html.escape(sp.get('sp_private_key', ''))+'</textarea>')
    self.add_content('  <label for="upload_sp_private_key_input" class="middlebutton">Upload private key</label><input id="upload_sp_private_key_input" type="file" style="display: none" onchange="uploadPem(event)"/></td></tr>')
    self.add_content('<tr id="sp_certificate" style="display: '+display_style+'"><td>SP Certificate</td><td><textarea name="sp_certificate" id="sp_certificate_input" rows="10" class="intable">'+html.escape(sp.get('sp_certificate', ''))+'</textarea>')
    self.add_content('  <label for="upload_sp_certificate_input" class="middlebutton">Upload certificate</label><input id="upload_sp_certificate_input" type="file" style="display: none" onchange="uploadPem(event)"/></td></tr>')
    self.add_content('<tr id="sp_download_local_certificate" style="display: '+display_style+'"><td>Local certificate</td><td><button type="button" class="middlebutton" onclick="downloadLocalCertificate()">Download certificate</button></td></tr>')
    
    self.add_content('</table>')

    self.add_content('<h3>General parameters</h3>')
    self.add_content('<table class="fixed">')
    
    self.add_content('<tr><td>NameID Policy</td><td>')
    self.add_content('<div class="select-editable" style="width: 520px;">')
    self.add_content('<select onchange="this.nextElementSibling.value=this.value" style="width: 520px;">')
    nameid_list = [
      'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
      'urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName',
      'urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:entity',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      'urn:oasis:names:tc:SAML:2.0:nameid-format:transient',
      ]
    for option in nameid_list:
      self.add_content('<option value="'+option+'">'+option+'</option>')
    self.add_content('</select>')
    self.add_content('<input name="nameid_policy" value="'+html.escape(sp.get('nameid_policy', ''))+'" class="intable" type="text" style="width: 500px;">')
    self.add_content('</div>')
    self.add_content('</td></tr>')
    
    self.add_content('<tr><td>Authentication binding</td><td><select name="authentication_binding" class="intable">')
    for value in ('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'):
      selected = ''
      if value == sp.get('authentication_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    checked = ''
    if Configuration.is_on(sp.get('sign_auth_request', 'off')):
      checked = ' checked'
    self.add_content('<tr><td>Sign authentication request</td><td><input name="sign_auth_request" type="checkbox"'+checked+'></td></tr>')

    self.add_content('<tr><td>Logout binding</td><td><select name="logout_binding" class="intable">')
    for value in ('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'):
      selected = ''
      if value == sp.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    checked = ''
    if Configuration.is_on(sp.get('sign_logout_request', 'off')):
      checked = ' checked'
    self.add_content('<tr><td>Sign logout request</td><td><input name="sign_logout_request" type="checkbox"'+checked+'></td></tr>')
    
    self.add_content('</table>')
    self.add_content('<button type="submit" class="button">Save</button>')
    self.add_content('</form>')

    # TEMP !
    self.add_content("""
    <form name="dl_sp_metadata_form" action="downloadSPMetadata" method="POST">
    <input type="hidden" name="sp_id" value="blah"/>
    <input type="hidden" name="nom" value="valeur"/>
    </form>
    """)


    self.add_content("""
    <script>
    
    window.addEventListener('load', (event) => {
      if (document.sp.sp_acs_url.value == '') {
        document.sp.sp_acs_url.value = window.location.origin + '/client/saml/login/acs';
      }
      if (document.sp.sp_slo_url.value == '') {
        document.sp.sp_slo_url.value = window.location.origin + '/client/saml/logout/callback';
      }
    });
    
    function changeSPKeyConfiguration() {
      var server_display_style = 'none'
      var local_display_style = 'table-row'
      if (document.sp.sp_key_configuration.value == 'Server keys') {
        server_display_style = 'table-row'
        local_display_style = 'none'
      }
      document.getElementById('sp_download_server_certificate').style.display = server_display_style;
      ['sp_private_key', 'sp_certificate', 'sp_download_local_certificate'].forEach(function(item, index) {
        document.getElementById(item).style.display = local_display_style;
      });
      document.getElementById('generate_keys').style.display = (local_display_style == 'none' ? 'none' : 'inline');
    }
    
    function downloadLocalCertificate() {
    
      certificate = document.sp.sp_certificate.value
      if (!certificate.startsWith('-----BEGIN CERTIFICATE-----')) {
        segments = certificate.match(/.{1,64}/g)
        certificate = '-----BEGIN CERTIFICATE-----\\n'+segments.join('\\n')+'\\n-----END CERTIFICATE-----'
      }
      
      var element = document.createElement('a');
      element.setAttribute('href', 'data:application/x-pem-file;charset=utf-8,' + encodeURIComponent(certificate));
      element.setAttribute('download', 'aduneo.crt');

      element.style.display = 'none';
      document.body.appendChild(element);

      element.click();

      document.body.removeChild(element);
    }
    
    
    function downloadSPMetadata() {
      
      filename = document.sp.sp_id.value
      if (filename == '') {
        filename = document.sp.name.value
      }
      if (filename == '') {
        filename = 'spMetadata'
      }
    
      let form = document.createElement("form");
      form.setAttribute("method", "POST");
      form.setAttribute("action", "downloadSPMetadata");

      
      let input = document.createElement("input");
      input.setAttribute("type", "hidden");
      input.setAttribute("name", "filename");
      input.setAttribute("value", filename);
      form.appendChild(input);

      addValueToForm(form, 'sp_entity_id')
      addValueToForm(form, 'sp_acs_url')
      addValueToForm(form, 'sp_slo_url')
      addValueToForm(form, 'sp_key_configuration')
      addValueToForm(form, 'sp_private_key')
      addValueToForm(form, 'sp_certificate')
      addValueToForm(form, 'nameid_policy')
      addValueToForm(form, 'authentication_binding')
      addValueToForm(form, 'logout_binding')
      addCheckedToForm(form, 'sign_auth_request')
      addCheckedToForm(form, 'sign_logout_request')

      document.body.appendChild(form);
      form.submit()
      document.body.removeChild(form);    
    }

    function addValueToForm(form, inputName) {
      let input = document.createElement("input");
      input.setAttribute("type", "hidden");
      input.setAttribute("name", inputName);
      input.setAttribute("value", document.sp[inputName].value);
      form.appendChild(input);
    }
    
    
    function addCheckedToForm(form, inputName) {
      let input = document.createElement("input");
      input.setAttribute("type", "hidden");
      input.setAttribute("name", inputName);
      input.setAttribute("value", document.sp[inputName].checked ? "true" : "false");
      form.appendChild(input);
    }
    
    
    function generateKeys() {

      var xhttp = new XMLHttpRequest();
      xhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
          jsonResponse = JSON.parse(xhttp.responseText);
          document.getElementById("sp_private_key_input").innerHTML = stripPEM(jsonResponse.private_key);
          document.getElementById("sp_certificate_input").innerHTML = stripPEM(jsonResponse.certificate);
        }
      };
      xhttp.open("GET", "/generatecertificate", true);
      xhttp.send();
    }
    
    
    function stripPEM(pem) {
      items = pem.split('\\n');
      items.shift();
      items.pop();
      items.pop();
      return items.join('');
    }

    function openConsole() {
        window.open("/webconsole", "console", "directories=no,titlebar=no,toolbar=no,location=no,status=no,menubar=no,scrollbars=no,resizable=no,height=500, width=500");
      }    
    </script>""")
    
    self.send_page()


  @register_url(url='modifyclientold', method='POST')
  def modify(self):
  
    """
    Crée ou modifie un client SAML dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    Versions:
    06/03/2021 (mpham) : version initiale
    03/03/2023 (mpham) : cas où le nom n'est pas renseigné
    """

    name = self.post_form['name']
    if name == '':
      name = 'SAML SP'
    
    sp_id = self.post_form['sp_id']
    if sp_id == '':
      sp_id = self.generate_spid(name, self.conf['saml_clients'].keys())
      self.conf['saml_clients'][sp_id] = {}
    
    sp = self.conf['saml_clients'][sp_id]
    
    sp['name'] = name
    for item in ['idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_certificate', 'sp_entity_id', 'sp_acs_url', 'sp_slo_url', 
    'sp_key_configuration', 'sp_private_key', 'sp_certificate', 'nameid_policy', 'authentication_binding', 'logout_binding']:
      if self.post_form[item] == '':
        sp.pop(item, None)
      else:
        sp[item] = self.post_form[item]

    for item in ['sign_auth_request', 'sign_logout_request']:
      if item in self.post_form:
        sp[item] = 'on'
      else:
        sp[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection('/')


  @register_url(url='removeclientold', method='GET')
  def remove(self):
  
    """
    Supprime un client SAML
    
    mpham 06/03/2021
    """

    sp_id = self.get_query_string_param('id')
    if sp_id is not None:
      self.conf['saml_clients'].pop(sp_id, None)
      Configuration.write_configuration(self.conf)
      
    self.send_redirection('/')


  def _get_clientfedid_certificate(self) -> str:
    """ Retourne le certificat SAML par défaut de ClientFedID
    
    Returns:
      certificat au format Base64 (PEM sans les délimiteurs)
      
    Versions:
      01/01/2025 (mpham) version initiale
    """
    
    certificate = None
    
    crt_file_path = self._check_clientfedid_certificate_exists()
    with open(crt_file_path, 'r') as crt_file:
      pem_certificate = crt_file.read()
      if pem_certificate.startswith('-----BEGIN CERTIFICATE-----'):
        certificate = pem_certificate.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\r', '').replace('\n', '').strip()
      else:
        certificate = pem_certificate.strip()
    
    return certificate
    

  def _check_clientfedid_certificate_exists(self) -> str:
    """ Vérifie que le certificat SAML par défaut existe
    
    dans les fichiers
    - conf/aduneo_saml.key pour la clé privée
    - conf/aduneo_saml.crt pour le certificat
    
    Le crée sinon.
    
    Returns:
      Certificate file path

    Versions:
      21/01/2023 (mpham) version initiale
      01/01/2025 (mpham) déplacé ver SAMLClientAdmin et adapté
    """
    
    key_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.key')
    crt_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.crt')
    
    if not os.path.isfile(key_file_path) or not os.path.isfile(crt_file_path):
      logging.info("Default SAML certificate does not exist, a key and certificate are generated")

      CryptoTools.generate_self_signed_certificate('https://www.aduneo.com', key_file_path, crt_file_path)
      
    return crt_file_path


  @register_url(url='downloadcficertificate', method='GET')
  def download_clientdefid_certificate(self):
    """
    Télécharge le certificat du serveur (utilisé pour SAML)

    Le crée s'il n'existe pas
    
    Versions:
      21/01/2023 (mpham) version initiale
      01/01/2025 (mpham) déplacé ver SAMLClientAdmin et adapté
    """

    try:
      crt_file_path = self._check_clientfedid_certificate_exists()
    except:
      send_page('Certificate not configured', code=400, clear_buffer=True)
      return
    
    self.download_file(crt_file_path, content_type='application/x-pem-file')

