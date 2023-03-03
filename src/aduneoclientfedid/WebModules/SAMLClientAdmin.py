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
from ..BaseServer import register_web_module, register_url
from ..Configuration import Configuration

import datetime
import html
import lxml
import lxml.builder
import os


@register_web_module('/client/saml/admin')
class SAMLClientAdmin(BaseHandler):
  
  @register_url(url='modifyclient', method='GET')
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


  @register_url(url='modifyclient', method='POST')
  def modify(self):
  
    """
    Crée ou modifie un client SAML dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 06/03/2021
    """
    
    sp_id = self.post_form['sp_id']
    if sp_id == '':
      sp_id = self.generate_spid(self.post_form['name'], self.conf['saml_clients'].keys())
      self.conf['saml_clients'][sp_id] = {}
    
    sp = self.conf['saml_clients'][sp_id]
    
    for item in ['name', 'idp_entity_id', 'idp_sso_url', 'idp_slo_url', 'idp_certificate', 'sp_entity_id', 'sp_acs_url', 'sp_slo_url', 
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


  @register_url(url='removeclient', method='GET')
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


  def generate_spid(self, name, existing_names):
    
    """
    Génère un identifiant à partir d'un nom
    en ne retenant que les lettres et les chiffres
    et en vérifiant que l'identifiant n'existe pas déjà
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    """
    
    base = name
    ok = False
    rank = 0
    
    while not ok:
      id = ''.join(c for c in base.casefold() if c.isalnum())
      if id == '':
        id = 'saml_sp'
      if rank > 0:
        id = id+str(rank)
      
      if id in existing_names:
        rank = rank+1
      else:
        ok = True
        
    return id


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
