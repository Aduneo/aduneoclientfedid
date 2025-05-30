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
import logging
import lxml
import lxml.builder
import os
import uuid


@register_web_module('/client/saml/admin')
class SAMLClientAdmin(BaseHandler):

  @register_page_url(url='modifyclient', method='GET', template='page_default.html', continuous=True)
  def modify_client_router(self):
    """ Sélection du mode de modification du client :
      
      On a en effet deux interfaces pour modifier un client, en fonction de l'état de la configuration
        - modification combinée IdP + client, quand un IdP n'a qu'une application du même type : modify_single
        - modification différencée IdP et les différents clients qu'il gère                    : modify_multi
        
    Versions:
      01/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
      31/01/2025 (mpham) on n'affiche les paramètres de l'IdP dans tous les cas si on a un seul SP ou pas de SP
    """

    idp_id = self.get_query_string_param('idpid', '')
    if idp_id == '':
      # Création d'un IdP
      self.modify_single_display()
    else:
      # Modification d'un IdP
      idp = self.conf['idps'].get(idp_id)
      if not idp:
        raise AduneoError(f"IdP {idp_id} not found in configuration")

      saml_clients = idp.get('saml_clients', {})  
      
      app_id = self.get_query_string_param('appid', '')
      if app_id == '':
        # Création d'un nouveau SP
        if len(saml_clients) == 0:
          self.modify_single_display()
        else:
          self.modify_multi_display()
      else:
        # Modification d'un SP
        if len(saml_clients) == 1:
          self.modify_single_display()
        else:
          self.modify_multi_display()
      

  def modify_single_display(self):
    """ Modification des paramètres de l'IdP et du client sur la même page
    
    Versions:
      01/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
      09/01/2025 (mpham) possibilités de l'IdP en termes de binding
      31/01/2025 (mpham) création d'un SP pour un IdP existant
      25/02/2025 (mpham) modification du nom du client
    """

    idp_id = self.get_query_string_param('idpid', '')
    app_id = self.get_query_string_param('appid', '')
    if idp_id == '':
      # Création
      idp = {'idp_parameters': {}}
    else:
      idp = self.conf['idps'][idp_id]

    idp_params = idp['idp_parameters']
    saml_params = idp_params.get('saml', {})
    saml_clients = idp.get('saml_clients', {})
    app_params = saml_clients.get(app_id, {})

    # possibilités de l'IdP en binding
    idp_authentication_binding_capabilities = saml_params.get('idp_authentication_binding_capabilities')
    if not idp_authentication_binding_capabilities:
      idp_authentication_binding_capabilities = self.conf.get('/default/saml/idp_authentication_binding_capabilities')
      if not idp_authentication_binding_capabilities:
        idp_authentication_binding_capabilities = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']

    idp_logout_binding_capabilities = saml_params.get('idp_logout_binding_capabilities')
    if not idp_logout_binding_capabilities:
      idp_logout_binding_capabilities = self.conf.get('/default/saml/idp_logout_binding_capabilities')
      if not idp_logout_binding_capabilities:
        idp_logout_binding_capabilities = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']

    form_content = {
      'idp_id': idp_id,
      'idp_name': idp.get('name', ''),
      'app_id': app_id,
      'app_name': app_params.get('name', ''),
      'idp_entity_id': saml_params.get('idp_entity_id', ''),
      'idp_sso_url': saml_params.get('idp_sso_url', ''),
      'idp_slo_url': saml_params.get('idp_slo_url', ''),
      'idp_certificate': saml_params.get('idp_certificate', ''),
      'idp_authentication_binding_capabilities': '\t'.join(idp_authentication_binding_capabilities),
      'idp_logout_binding_capabilities': '\t'.join(idp_logout_binding_capabilities),
      'sp_entity_id': app_params.get('sp_entity_id', ''),
      'sp_acs_url': app_params.get('sp_acs_url', ''),
      'sp_slo_url': app_params.get('sp_slo_url', ''),
      'sp_key_configuration': app_params.get('sp_key_configuration', 'clientfedid_keys'),
      'sp_private_key': app_params.get('sp_private_key', ''),
      'sp_certificate': app_params.get('sp_certificate', SAMLClientAdmin._get_clientfedid_certificate()),
      'nameid_policy': app_params.get('nameid_policy', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'),
      'authentication_binding': app_params.get('authentication_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_auth_request': Configuration.is_on(app_params.get('sign_auth_request', 'off')),
      'logout_binding': app_params.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_logout_request': Configuration.is_on(app_params.get('sign_logout_request', 'off')),
      }
    
    form = CfiForm('samladminsingle', form_content, action='modifyclientsingle', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('idp_name', label='IdP name') \
      .text('app_name', label='SP name') \
      .start_section('idp_parameters', title="IdP parameters") \
        .upload_button('upload_idp_metadata', label='Upload IdP metadata', on_upload="parseIdPMetadata(upload_content, cfiForm);") \
        .text('idp_entity_id', label='IdP entity ID', clipboard_category='idp_entity_id') \
        .text('idp_sso_url', label='IdP SSO URL', clipboard_category='idp_sso_url') \
        .text('idp_slo_url', label='IdP SLO URL', clipboard_category='idp_slo_url') \
        .textarea('idp_certificate', label='IdP certificate', rows=10, clipboard_category='idp_certificate', upload_button='Upload IdP certificate') \
        .hidden('idp_authentication_binding_capabilities') \
        .hidden('idp_logout_binding_capabilities') \
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
          values = {value: value for value in idp_authentication_binding_capabilities},
          default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          ) \
        .check_box('sign_auth_request', label='Sign authentication request') \
        .closed_list('logout_binding', label='Logout binding', 
          values = {value: value for value in idp_logout_binding_capabilities},
          default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
          ) \
        .check_box('sign_logout_request', label='Sign logout request') \
      .end_section() \
      
    form.set_title('SAML SP configuration'+('' if form_content['idp_name'] == '' else ': '+form_content['idp_name']))
    form.add_button('Cancel', f'/client/idp/admin/display?idpid={idp_id}', display='all')
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
      09/01/2025 (mpham) possibilités de l'IdP en termes de binding
      31/01/2025 (mpham) création d'un SP pour un IdP existant
      14/02/2025 (mpham) en création, un client vide était créé
      25/02/2025 (mpham) modification du nom du client
      30/05/2025 (mpham) les paramètres SAML de l'IdP n'était pas créés quand on ajoutait une fonctionnalité SAML d'un Idp n'en ayant pas
    """
    
    idp_id = self.post_form['idp_id']
    app_id = self.post_form['app_id']
    if idp_id == '':
      # Création de l'IdP
      idp_id = self._generate_unique_id(name=self.post_form['idp_name'].strip(), existing_ids=self.conf['idps'].keys(), default='idp', prefix='idp_')
      self.conf['idps'][idp_id] = {'idp_parameters': {'saml': {}}}
    idp = self.conf['idps'][idp_id]

    if app_id == '':
      # Création du SP
      app_id = f'saml_{idp_id[4:]}_sp'
      if not idp.get('saml_clients'):
        idp['saml_clients'] = {}
      idp['saml_clients'][app_id] = {}
    
    idp_params = idp['idp_parameters']
    if not idp_params.get('saml'):
      idp_params['saml'] = {}
    saml_params = idp_params['saml']
    app_params = idp['saml_clients'][app_id]
    
    if self.post_form['idp_name'] == '':
      self.post_form['idp_name'] = idp_id
    idp['name'] = self.post_form['idp_name'].strip()
    
    if self.post_form['app_name'] == '':
      self.post_form['app_name'] = 'SAML SP'
    app_params['name'] = self.post_form['app_name'].strip()
    
    for item in ['idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_certificate']:
      if self.post_form.get(item, '') == '':
        saml_params.pop(item, None)
      else:
        saml_params[item] = self.post_form[item].strip()

    for item in ['idp_authentication_binding_capabilities', 'idp_logout_binding_capabilities']:
      if self.post_form.get(item, '') == '':
        saml_params.pop(item, None)
      else:
        saml_params[item] = self.post_form[item].split('\t')
      
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
      03/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
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
        app_params = idp['saml_clients'][app_id]
        
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
    """ Crée ou modifie une App SAML pour un IdP existant (mode multi)
    
    Si l'identifiant existe, ajoute un suffixe numérique
    
    Versions:
      03/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """
    
    idp_id = self.post_form['idp_id']
    idp = self.conf['idps'][idp_id]
    
    app_id = self.post_form['app_id']
    if app_id == '':
      # Création
      if not idp.get('saml_clients'):
        idp['saml_clients'] = {}
      
      app_id = self._generate_unique_id(name=self.post_form['name'].strip(), existing_ids=idp['saml_clients'].keys(), default='op', prefix=f'saml_{idp_id[4:]}_')
      idp['saml_clients'][app_id] = {}
    
    app_params = idp['saml_clients'][app_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = app_id

    app_params['name'] = self.post_form['name'].strip()
    
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
    """ Page de suppression d'un client SAML
    
    Versions:
      03/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
      idp = copy.deepcopy(self.conf['idps'][idp_id])
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['saml_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"SAML client {app_id} does not exist", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      
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
      app_form.set_title('Remove SAML app '+(' '+app_params['name'] if app_params.get('name') else ''))
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
    Supprime un client SAML

    Versions:
      03/01/2025 (mpham) version initiale adaptée de OIDCClientAdmin
    """

    try:

      idp_id = self.get_query_string_param('idpid', '')
      if idp_id == '':
        raise AduneoError(f"IdP {idp_id} does not exist", action="/")
      idp = self.conf['idps'][idp_id]
      
      app_id = self.get_query_string_param('appid', '')
      app_params = idp['saml_clients'].get(app_id)
      if not app_params:
        raise AduneoError(f"SAML client {app_id} does not exist", action=f"/client/idp/admin/display?idpid={idp_id}")

      del idp['saml_clients'][app_id]
      Configuration.write_configuration(self.conf)
      self.send_redirection(f"/client/idp/admin/display?idpid={idp_id}")
      
    except AduneoError as e:
      self.send_redirection(e.action)


  def get_app_form(handler, app_params:dict):
    """ Retourne un RequesterForm avec un client SAML (sans les paramètres de l'IdP)
    
    Args:
      handler: objet de type BaseHandler, pour accès à la configuration
      app_params: dict avec les paramètres du client SAML (SP), dans le formalisme du fichier de configuration
             Attention : il faut ajouter deux champs
              - idp_id avec l'identifiant unique de l'IdP
              - app_id avec l'identifiant unique du client
             
    Returns:
      objet RequesterForm
    
    Versions:
      03/01/2025 (mpham) version initiale adaptée de modify_single_display
    """

    form_content = {
      'idp_id': app_params['idp_id'],
      'app_id': app_params['app_id'],
      'name': app_params.get('name', ''),
      'sp_entity_id': app_params.get('sp_entity_id', ''),
      'sp_acs_url': app_params.get('sp_acs_url', ''),
      'sp_slo_url': app_params.get('sp_slo_url', ''),
      'sp_key_configuration': app_params.get('sp_key_configuration', 'clientfedid_keys'),
      'sp_private_key': app_params.get('sp_private_key', ''),
      'sp_certificate': app_params.get('sp_certificate', SAMLClientAdmin._get_clientfedid_certificate()),
      'nameid_policy': app_params.get('nameid_policy', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'),
      'authentication_binding': app_params.get('authentication_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_auth_request': Configuration.is_on(app_params.get('sign_auth_request', 'off')),
      'logout_binding': app_params.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
      'sign_logout_request': Configuration.is_on(app_params.get('sign_logout_request', 'off')),
      }
    
    form = CfiForm('samladminmulti', form_content, action='modifymulti', submit_label='Save') \
      .hidden('idp_id') \
      .hidden('app_id') \
      .text('name', label='Name') \
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
      
    form.set_title('SAML authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', handler.conf.is_on('/preferences/clipboard/remember_secrets', False))

    return form


  def _get_clientfedid_private_key() -> str:
    """ Retourne la clé privée SAML par défaut de ClientFedID
    
    Returns:
      clé privée au format Base64 (PEM sans les délimiteurs)
      
    Versions:
      05/01/2025 (mpham) version initiale
    """
    
    private_key = None
    
    key_file_path = SAMLClientAdmin._check_clientfedid_private_key_exists()
    with open(key_file_path, 'r') as key_file:
      pem_private_key = key_file.read()
      if pem_private_key.startswith('-----BEGIN PRIVATE KEY-----'):
        private_key = pem_private_key.replace('-----BEGIN PRIVATE KEY-----', '').replace('-----END PRIVATE KEY-----', '').replace('\r', '').replace('\n', '').strip()
      else:
        private_key = pem_private_key.strip()
    
    return private_key
    

  def _get_clientfedid_certificate() -> str:
    """ Retourne le certificat SAML par défaut de ClientFedID
    
    Returns:
      certificat au format Base64 (PEM sans les délimiteurs)
      
    Versions:
      01/01/2025 (mpham) version initiale
    """
    
    certificate = None
    
    crt_file_path = SAMLClientAdmin._check_clientfedid_certificate_exists()
    with open(crt_file_path, 'r') as crt_file:
      pem_certificate = crt_file.read()
      if pem_certificate.startswith('-----BEGIN CERTIFICATE-----'):
        certificate = pem_certificate.replace('-----BEGIN CERTIFICATE-----', '').replace('-----END CERTIFICATE-----', '').replace('\r', '').replace('\n', '').strip()
      else:
        certificate = pem_certificate.strip()
    
    return certificate
    

  def _check_clientfedid_private_key_exists() -> str:
    """ Vérifie que la clé privée SAML par défaut existe
    
    dans le fichier
    - conf/aduneo_saml.key
    
    Le crée sinon.
    
    Returns:
      Chemin complet vers la fichier contenant la clé

    Versions:
      05/01/2025 (mpham) version initiale
    """
    
    return SAMLClientAdmin._check_clientfedid_keys_exists().get('private_key_path')


  def _check_clientfedid_certificate_exists() -> str:
    """ Vérifie que le certificat SAML par défaut existe
    
    dans le fichier
    - conf/aduneo_saml.crt
    
    Le crée sinon.
    
    Returns:
      Certificate file path

    Versions:
      21/01/2023 (mpham) version initiale
      01/01/2025 (mpham) déplacé ver SAMLClientAdmin et adapté
      05/01/2025 (mpham) appel de _check_clientfedid_keys_exists()
    """
    
    return SAMLClientAdmin._check_clientfedid_keys_exists().get('certificate_path')


  def _check_clientfedid_keys_exists() -> dict:
    """ Vérifie que le certificat SAML par défaut existe
    
    dans les fichiers
    - conf/aduneo_saml.key pour la clé privée
    - conf/aduneo_saml.crt pour le certificat
    
    Le crée sinon.
    
    Returns:
      dict avec
        - private_key_path: chemin complet vers la clé privée
        - certificate_path: chemin complet vers le certificat

    Versions:
      05/01/2025 (mpham) adapté de l'ancien _check_clientfedid_certificate_exists()
    """
    
    key_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.key')
    crt_file_path = os.path.join(Configuration.conf_dir, 'aduneo_saml.crt')
    
    if not os.path.isfile(key_file_path) or not os.path.isfile(crt_file_path):
      logging.info("Default SAML certificate does not exist, a key and certificate are generated")

      CryptoTools.generate_self_signed_certificate('https://www.aduneo.com', key_file_path, crt_file_path)
      
    return {'certificate_path': crt_file_path, 'private_key_path': key_file_path}


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

