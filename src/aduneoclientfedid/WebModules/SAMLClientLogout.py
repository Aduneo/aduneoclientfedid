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
from ..BaseServer import BaseServer
from ..BaseServer import register_web_module, register_url
from ..Configuration import Configuration
from datetime import datetime
from lxml import etree
import base64
import html
import logging
import os
import requests
import traceback
import urllib.parse
import uuid
import xmlsec
import zlib


@register_web_module('/client/saml/logout')
class SAMLClientLogout(BaseHandler):
 
  @register_url(url='preparerequest', method='GET')
  def prepare_request(self):

    logging.info("Preparation of a SAML logout request")

    sp_id = self.get_query_string_param('id')
    if sp_id is None:
      raise AduneoError("Client identifier not found in query string")
    logging.info("for client "+sp_id)

    if sp_id not in self.conf['saml_clients']:
      raise AduneoError("Client identifier not found in configuration")
    
    # Récupération du NameID et de son Format dans la session
    nameid_info = self.get_session_value('session_saml_client_'+sp_id)
    if nameid_info is None:
      raise AduneoError("No session found for client "+sp_id)
    logging.info("and identity "+str(nameid_info))

    nameid = nameid_info.get('NameID', '')
    nameid_format = nameid_info.get('Format', '')
    session_index = nameid_info.get('SessionIndex', '')

    sp = self.conf['saml_clients'][sp_id]
    
    # récupération des clés
    if sp.get('sp_key_configuration').casefold() == 'server keys':
      self.log_info('Fetching default SAML keys as SP keys')
      
      try:
        cert_path = self.hreq.check_saml_certificate_exists()
        with open(cert_path) as cert_file:
          sp['sp_certificate'] = ''.join(cert_file.readlines()[1:-1]).replace('\n', '')
        
        (cert_path_without_ext, ext) = os.path.splitext(cert_path)
        key_path = cert_path_without_ext+'.key'
        with open(key_path) as key_file:
          sp['sp_private_key'] = ''.join(key_file.readlines()[1:-1]).replace('\n', '')
          
      except Exception as e:
        print(e)
        self.log_info("  Default SAML certificate not found or read error")
        sp['sp_certificate'] = ''
        sp['sp_private_key'] = ''
            
    self.add_content("<h1>SAML logout for SP "+sp["name"]+"</h1>")
    self.add_content('<form name="request" action="/client/saml/logout/sendrequest" method="post">')
    self.add_content('<input name="sp_id" value="'+html.escape(sp_id)+'" type="hidden" />')
    self.add_content('<table class="fixed">')
     
    self.add_content('<tr><td>IdP Logout URL</td><td><input name="idp_slo_url" value="'+html.escape(sp.get('idp_slo_url', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>SP Entity ID</td><td><input name="sp_entity_id" value="'+html.escape(sp.get('sp_entity_id', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>NameID</td><td><input name="nameid" value="'+html.escape(nameid)+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>NameID Format</td><td><input name="nameid_format" value="'+html.escape(nameid_format)+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>SessionIndex</td><td><input name="session_index" value="'+html.escape(session_index)+'" class="intable" type="text"></td></tr>')
      
    self.add_content('<tr><td>Logout binding</td><td><select name="logout_binding" class="intable" onchange="reset_keys_fields()">')
    for value in ('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'):
      selected = ''
      if value == sp.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')

    checked = ''
    if Configuration.is_on(sp.get('sign_logout_request', 'off')):
      checked = ' checked'
    self.add_content('<tr><td>Sign logout request</td><td><input name="sign_logout_request" type="checkbox"'+checked+' onchange="reset_keys_fields()"></td></tr>')

    display_sp_private_key = 'none'
    display_sp_certificate = 'none'
    if Configuration.is_on(sp.get('sign_logout_request', 'off')):
      display_sp_private_key = 'table-row'
      if sp.get('logout_binding') == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
        display_sp_certificate = 'table-row'

    self.add_content('<tr id="sp_private_key_row" style="display: '+display_sp_private_key+'"><td>SP Private Key</td><td><textarea name="sp_private_key" rows="10" class="intable">'+html.escape(sp['sp_private_key'])+'</textarea></td></tr>')
    self.add_content('<tr id="sp_certificate_row" style="display: '+display_sp_certificate+'"><td>SP Certificate</td><td><textarea name="sp_certificate" rows="10" class="intable">'+html.escape(sp['sp_certificate'])+'</textarea></td></tr>')

    self.add_content('</table>')
    
    self.add_content('<div style="padding-top: 20px; padding-bottom: 12px;"><div style="padding-bottom: 6px;"><strong>Logout request</strong> <img title="Copy request" class="smallButton" src="/images/copy.png" onClick="copyRequest()"/></div>')
    self.add_content('<span id="logout_request" style="font-size: 14px;"></span></div>')
    self.add_content('<input name="logout_request" type="hidden">')
    
    self.add_content('<button type="submit" class="button">Send to IdP</button>')
    self.add_content('</form>')
      
    self.add_content("""
      <script>
      function reset_keys_fields() {
        if (document.request.sign_logout_request.checked) {
          document.getElementById('sp_private_key_row').style.display = 'table-row';
          if (document.request.logout_binding.value == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST') {
            document.getElementById('sp_certificate_row').style.display = 'table-row';
          } else {
            document.getElementById('sp_certificate_row').style.display = 'none';
          }
        } else {
          document.getElementById('sp_private_key_row').style.display = 'none';
          document.getElementById('sp_certificate_row').style.display = 'none';
        }
      }
      </script>
    """)
    
    self.send_page()
      
      
  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    
    logging.info('Redirection to SAML IdP requested for logout')
    
    logout_binding = self.post_form.get('logout_binding', '')
    logging.info('for binding '+logout_binding)
    if logout_binding == '':
      error_message = 'Logout binding not found'
      logging.error(error_message)
      self.send_page(error_message)
    elif logout_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect':
      self._send_request_redirect()
    elif logout_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
      self._send_request_post()
    else:
      error_message = 'Logout binding '+authentication_binding+' not supported'
      logging.error(error_message)
      self.send_page(error_message)


  def _send_request_post(self):

    req_id = 'id'+str(uuid.uuid4())
    logging.info('Constructing logout request '+req_id)
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')     # 2014-07-16T23:52:45Z

    sp_id = self.post_form.get('sp_id', '')
    if sp_id == '':
      raise AduneoError('SP ID not found')
    logging.info('For SP '+sp_id)
    
    sp = self.conf['saml_clients'].get(sp_id)
    if sp is None:
      raise AduneoError('SP '+sp_id+' not found in configuration')

    req_template = """
    <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{req_id}" Version="2.0" IssueInstant="{timestamp}" Destination="{destination}">
      <saml:Issuer>{issuer}</saml:Issuer>
      <saml:NameID{format}>{nameid}</saml:NameID>
      <samlp:SessionIndex>{session_index}</samlp:SessionIndex>
    </samlp:LogoutRequest>
    """
    
    format = ''
    nameid_format = self.post_form.get('nameid_format', '')
    if nameid_format != '':
      format = ' Format="'+nameid_format+'"'

    xml_req = req_template.format(
      req_id = req_id, 
      timestamp = timestamp, 
      destination = self.post_form['idp_slo_url'], 
      issuer = self.post_form['sp_entity_id'],
      format = format,
      nameid = self.post_form['nameid'],
      session_index = self.post_form['session_index']
      )
    
    logging.info("Logout request:")
    logging.info(xml_req)
    
    byte_xml_req = xml_req.encode()

    sign_logout_request = self.post_form.get('sign_logout_request', 'off')
    if Configuration.is_on(sign_logout_request):
    
      # Signature de la requête
      template = etree.fromstring(xml_req)
      xmlsec.tree.add_ids(template, ["ID"]) 

      # on crée le noeud pour la signature
      signature_node = xmlsec.template.create(
        template,
        c14n_method=xmlsec.Transform.EXCL_C14N,
        sign_method=xmlsec.Transform.RSA_SHA1,
        ns='ds')

      # Pour que le XML soit valide, il faut ajouter la signature après l'issuer
      issuer_el = template.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
      issuer_el.addnext(signature_node)
#      template.append(signature_node)
      ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1, uri='#'+req_id)
      xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
      xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
      key_info = xmlsec.template.ensure_key_info(signature_node)
      xmlsec.template.add_x509_data(key_info)  
      
      # Récupération des clés
      if self.post_form.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + self.post_form['sp_private_key'] + '\n-----END PRIVATE KEY-----'
      if self.post_form.get('sp_certificate', '') == '':
        raise AduneoError("Missing certificate, can't sign request")
      sp_certificate = '-----BEGIN CERTIFICATE-----\n' + self.post_form['sp_certificate'] + '\n-----END CERTIFICATE-----'

      # on signe le XML
      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      ctx.key.load_cert_from_memory(sp_certificate, xmlsec.KeyFormat.CERT_PEM)
      ctx.sign(signature_node)
      logging.info('Signed request:')
      logging.info(etree.tostring(template, pretty_print=True).decode())
      
      byte_xml_req = etree.tostring(template)
      
    base64_req = base64.b64encode(byte_xml_req).decode()
    logging.info("Base64 encoded logout request:")
    logging.info(base64_req)

    self.send_page_top(200, template=False)
    
    self.add_content('<html><body onload="document.saml.submit()">')
    self.add_content('<html><body>')
    self.add_content('<form name="saml" action="'+self.post_form['idp_slo_url']+'" method="post">')
    self.add_content('<input type="hidden" name="SAMLRequest" value="'+html.escape(base64_req)+'" />')
    self.add_content('<input type="hidden" name="RelayState" value="'+html.escape(sp_id)+'" />')
    #self.add_content('<input type="submit"/>')
    self.add_content('</form></body></html>')
    
    #print(html.escape(xml_req))


  def _send_request_redirect(self):

    req_id = 'id'+str(uuid.uuid4())
    logging.info('Constructing logout request '+req_id)
    timestamp = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')     # 2014-07-16T23:52:45Z

    sp_id = self.post_form.get('sp_id', '')
    if sp_id == '':
      raise AduneoError('SP ID not found')
    logging.info('For SP '+sp_id)
    
    sp = self.conf['saml_clients'].get(sp_id)
    if sp is None:
      raise AduneoError('SP '+sp_id+' not found in configuration')

    req_template = """
    <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{req_id}" Version="2.0" IssueInstant="{timestamp}" Destination="{destination}">
      <saml:Issuer>{issuer}</saml:Issuer>
      <saml:NameID{format}>{nameid} NameQualifier="{name_qualifier}"</saml:NameID>
      <samlp:SessionIndex>{session_index}</samlp:SessionIndex>
    </samlp:LogoutRequest>
    """
    
    format = ''
    nameid_format = self.post_form.get('nameid_format', '')
    if nameid_format != '':
      format = ' Format="'+nameid_format+'"'

    xml_req = req_template.format(
      req_id = req_id, 
      timestamp = timestamp, 
      destination = self.post_form['idp_slo_url'], 
      issuer = self.post_form['sp_entity_id'],
      format = format,
      name_qualifier = self.post_form['sp_entity_id'],
      nameid = self.post_form['nameid'],
      session_index = self.post_form['session_index']
      )
    
    logging.info("Logout request:")
    logging.info(xml_req)
    
    # on deflate la requête TODO : on pourra utiliser directement zlib.compress() en Python 3.11
    compress = zlib.compressobj(
            zlib.Z_DEFAULT_COMPRESSION, # level: 0-9
            zlib.DEFLATED,        # method: must be DEFLATED
            -zlib.MAX_WBITS,      # window size in bits:
                                  #   -15..-8: negate, suppress header
                                  #   8..15: normal
                                  #   16..30: subtract 16, gzip header
            zlib.DEF_MEM_LEVEL,   # mem level: 1..8/9
            0                     # strategy:
                                  #   0 = Z_DEFAULT_STRATEGY
                                  #   1 = Z_FILTERED
                                  #   2 = Z_HUFFMAN_ONLY
                                  #   3 = Z_RLE
                                  #   4 = Z_FIXED
    )
    deflated_req = compress.compress(xml_req.encode('iso-8859-1'))
    deflated_req += compress.flush()
    
    base64_req = base64.b64encode(deflated_req)
    logging.info("Base64 encoded deflated logout request:")
    logging.info(base64_req.decode())
    
    urlencoded_req = urllib.parse.quote_plus(base64_req) # TODO vérifier que ce n'est pas quote plutôt que quote_plus
    
    # Signature de la requête
    #   on construit le message SAMLRequest=value&RelayState=value&SigAlg=value
    #   (les valeurs doivent être URL-encoded)
    #   que l'on signe
    
    urlencoded_relay_state = urllib.parse.quote_plus(sp_id)

    message = 'SAMLRequest='+urlencoded_req+'&RelayState='+urlencoded_relay_state
    
    sign_logout_request = self.post_form.get('sign_logout_request', 'off')
    if Configuration.is_on(sign_logout_request):
    
      urlencoded_sig_alg = urllib.parse.quote_plus('http://www.w3.org/2000/09/xmldsig#rsa-sha1')
      
      message += '&SigAlg='+urlencoded_sig_alg
      logging.info('Signature message: '+message)

      xmlsec.enable_debug_trace(True)

      if self.post_form.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + self.post_form['sp_private_key'] + '\n-----END PRIVATE KEY-----'

      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      signature = ctx.sign_binary(message.encode(), xmlsec.constants.TransformRsaSha1)
      base64_signature = base64.b64encode(signature).decode()
      logging.info('Signature: '+base64_signature)

      message += '&signature=' + urllib.parse.quote_plus(base64_signature)

    url = self.post_form['idp_slo_url'] + '?' + message
    logging.info('URL: '+url)
    
    logging.info('Sending redirection')
    self.send_redirection(url)
    
    
  @register_url(url='callback', method='GET')
  @register_url(url='callback', method='POST')
  def callback(self):
    
    """
    Retour de logout
    
    mpham 15/03/2021
    mpham 20/01/2023 méthode HTTP-Redirect
    """

    logging.info('Logout call back')

    xml_resp = None
    relay_state = None
    
    if self.hreq.command == 'POST':

      # Problème cookie SameSite=Lax
      if self.hreq.headers.get('Cookie') is None:
        logging.error('Session cookie not sent')
        self.send_page_top(200, template=False, send_cookie=False)
        
        self.add_content('<html><body onload="document.saml.submit()">')
        self.add_content('<form name="saml" method="post">')
        for item in self.post_form:
          self.add_content('<input type="hidden" name="'+html.escape(item)+'" value="'+html.escape(self.post_form[item])+'" />')
        #self.add_content('<input type="submit" />')
        self.add_content('</form></body></html>')
        return

      logging.info(str(self.post_form))

      base64_resp = self.post_form.get('SAMLResponse', None)
      if base64_resp is None:
        raise AduneoError('SAMLResponse not found in POST data')
      xml_resp = base64.b64decode(base64_resp).decode()
      relay_state = self.post_form.get('RelayState')
      
    elif self.hreq.command == 'GET':
      
      quoted_resp = self.get_query_string_param('SAMLResponse')
      if quoted_resp is None:
        raise AduneoError('SAMLResponse not found in GET data')
      relay_state = self.get_query_string_param('RelayState')
      
      # on dézippe la réponse
      base64_resp = urllib.parse.unquote(quoted_resp)
      compressed_resp = base64.b64decode(base64_resp)
      decompressed_resp = zlib.decompress(compressed_resp, -zlib.MAX_WBITS)
      xml_resp = decompressed_resp.decode('iso-8859-1')

    logging.info(xml_resp)

    root_el = etree.fromstring(xml_resp.encode())
    
    status_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status')
    status_code_el = status_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
    status_code = status_code_el.attrib['Value']
    logging.info('Status code: '+status_code)

    self.add_content('<h2>Logout callback</h2>')
    self.add_content(status_code)
    self.send_page()
    
    if status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success':
      sp_id = relay_state
      if sp_id is not None:
        logging.info('Removing session for SP '+sp_id)
        self.logoff('saml_client_'+sp_id)

