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

import base64
import html
import logging
import os
import traceback
import urllib.parse
import uuid
import xmlsec
import zlib

from datetime import datetime
from lxml import etree
from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import BaseServer
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import CfiForm
from ..Configuration import Configuration
from .FlowHandler import FlowHandler
from .SAMLClientAdmin import SAMLClientAdmin


@register_web_module('/client/saml/logout')
class SAMLClientLogout(FlowHandler):
  """ SAML Logout
  
    Versions:
      04/01/2024 (mpham) version initiale adaptée de OIDCClientLogout
  """
 
  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=True)
  def prepare_request(self):

    try:

      self.log_info('--- Start SAML logout flow ---')

      # Récupération du contexte d'authentification
      if not self.context:
        idp_id = self.get_query_string_param('idpid', '')
        raise AduneoError("Can't retrieve request context from session", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")
      self.log_info(('  ' * 1)+'for context: '+self.context['context_id'])

      # Récupération des paramètres nécessaires à la déconnexion
      idp_params = self.context.idp_params

      app_params = None
      app_id = self.get_query_string_param('appid', '')
      app_params = self.context.app_params.get(app_id, None)
      if not app_params:
        # les paramètres du client ne sont pas dans le contexte, on va les chercher dans la configuration
        idp_id = self.get_query_string_param('idpid', '')
        if idp_id == '':
          raise AduneoError(f"IdP {idp_id} does not exist", button_label="Return to homepage", action="/")
        idp = copy.deepcopy(self.conf['idps'][idp_id])
        app_params = idp['saml_clients'].get(app_id)
        if not app_params:
          raise AduneoError(f"SAMl service provider {app_id} does not exist for IdP {idp_id}", button_label="Return to IdP page", action=f"/client/idp/admin/display?idpid={idp_id}")

      # Récupération des assertions pour le client
      assertions = {'__none__': 'None', '__input__': 'Direct Input'}
      default_assertion_wrapper = None
      for assertion_wrapper_key in sorted(self.context['saml_assertions'].keys(), reverse=True):
        assertion_wrapper = self.context['saml_assertions'][assertion_wrapper_key]
        if assertion_wrapper['app_id'] == app_id:
          assertions[assertion_wrapper['saml_assertion']] = assertion_wrapper['name']
          if not default_assertion_wrapper:
              default_assertion_wrapper = assertion_wrapper  

      relay_state = str(uuid.uuid4())

      form_content = {
        'hr_context': self.context['context_id'],
        'idp_slo_url': idp_params.get('idp_slo_url', ''),
        'sp_entity_id': app_params.get('sp_entity_id', ''),
        'name_id': default_assertion_wrapper.get('name_id', '') if default_assertion_wrapper else '',
        'name_id_format': default_assertion_wrapper.get('name_id_format', '') if default_assertion_wrapper else '',
        'session_index': default_assertion_wrapper.get('session_index', '') if default_assertion_wrapper else '',
        'logout_binding': app_params.get('logout_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        'sign_logout_request': Configuration.is_on(app_params.get('sign_logout_request', 'off')),
        'sp_private_key': '',
        'sp_certificate': app_params.get('sp_certificate', ''),
        'relay_state': relay_state,
        'request_id': 'id'+str(uuid.uuid4()),
        'logout_request': '',
      }
      
      form = CfiForm('samllogout', form_content, action='/client/saml/logout/sendrequest', mode='new_page') \
        .hidden('hr_context') \
        .hidden('request_id') \
        .start_section('idp_params', title="IdP parameters") \
          .text('idp_slo_url', label='IdP SLO URL', clipboard_category='idp_slo_url', on_change='updateLogoutRequest(cfiForm)') \
        .end_section() \
        .start_section('sp_parameters', title="SP parameters") \
          .text('sp_entity_id', label='SP entity ID', clipboard_category='sp_entity_id', on_change='updateLogoutRequest(cfiForm)') \
          .text('name_id', label='NameID', clipboard_category='name_id', on_change='updateLogoutRequest(cfiForm)') \
          .text('name_id_format', label='NameID format', clipboard_category='name_id_format', on_change='updateLogoutRequest(cfiForm)') \
          .text('session_index', label='Session index', clipboard_category='session_index', on_change='updateLogoutRequest(cfiForm)') \
          .closed_list('logout_binding', label='Logout binding',
            values = {'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'},
            default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            ) \
          .check_box('sign_logout_request', label='Sign logout request') \
          .textarea('sp_private_key', label='SP private key', rows=10, clipboard_category='sp_private_key', upload_button='Upload SP private key', displayed_when="@[sign_logout_request]") \
          .textarea('sp_certificate', label='SP certificate', rows=10, clipboard_category='sp_certificate', upload_button='Upload SP certificate', displayed_when="@[sign_logout_request]") \
        .end_section() \
        .start_section('logout_params', title="Logout request") \
          .text('relay_state', label='Relay state', clipboard_category='relay_state') \
          .textarea('logout_request', label='SAML logout request', rows=10, clipboard_category='logout_request', upload_button='Upload XML', on_load='updateLogoutRequest(cfiForm)') \
        .end_section() \

      self.add_javascript_include('/javascript/SAMLClientLogout.js')
      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())

    except AduneoError as error:
      self.add_html('<h4>Error: '+html.escape(str(error))+'</h4>')
      self.add_html(f"""
        <div>
          <span><a class="middlebutton" href="{error.action}">{error.button_label}</a></span>
        </div>
        """)
      self.send_page()
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Refresh error: '+html.escape(str(error))+'</h4>')
      self.send_page()

    self.send_page()

      
  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    """
      Prépare la requête de déconnexion SAML

    Versions:
      02/01/2025 (mpham) version initiale copiée d'OAuth 2 et de l'ancienne version de SAML
    """
    
    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      logging.info('Redirection to SAML IdP requested for logout')

      relay_state = self.post_form.get('relay_state', '')
      if relay_state == '':
        raise AduneoError("Relay state not found in request")
      self.log_info(f"  for relay state {relay_state}")

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(relay_state, self.context['context_id'])

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      for item in ['idp_slo_url']:
        idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dans le contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['sp_entity_id', 'logout_binding', 'sp_private_key', 'sp_certificate', 'request_id']:
        app_params[item] = self.post_form.get(item, '').strip()
        
      if 'sign_logout_request' in self.post_form:
        app_params['sign_logout_request'] = 'on'
      else:
        app_params['sign_logout_request'] = 'off'

      # récupération de la clé privée dans la configuration
      if app_params['sp_private_key'] == '':
        self.log_info("  private key not in form, retrieving it from configuration")
        conf_idp = self.conf['idps'][self.context.idp_id]
        conf_app = conf_idp['saml_clients'][self.context.app_id]
        if conf_app.get('sp_key_configuration', 'clientfedid_keys') == 'specific_keys':
          self.log_info("  private key was in the SP configuration")
          app_params['sp_private_key'] = conf_app.get('sp_private_key', '')
        else:
          self.log_info("  private key is the default SAML private key")
          app_params['sp_private_key'] = SAMLClientAdmin._get_clientfedid_private_key()
      
      logout_binding = app_params['logout_binding']
      logging.info('  with binding '+logout_binding)
      if logout_binding == '':
        error_message = 'Logout binding not found'
        logging.error(error_message)
        self.send_page(error_message)
      elif logout_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect':
        self._send_request_redirect()
      elif logout_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
        self._send_request_post()
      else:
        error_message = 'Logout binding '+logout_binding+' not supported'
        logging.error(error_message)
        self.send_page(error_message)

    except Exception as error:
      if not isinstance(error, AduneoError):
        self.log_error(traceback.format_exc())
      self.log_error("""Can't send the request to the IdP, technical error {error}""".format(error=error))
      self.add_html("""<div>Can't send the request to the IdP, technical error {error}</div>""".format(error=error))
      self.add_html(f"""
        <div>
          <span><a class="middlebutton" href="{f"/client/idp/admin/display?idpid={self.context.idp_id}"}">IdP parameters</a></span>
        </div>
        """)
      self.send_page()


  def _send_request_post(self):
    """ Envoie la requête de déconnexion SAML en POST

    Versions:
      05/01/2025 (mpham) version initiale copiée d'OAuth 2 et de l'ancienne version de SAML
    """

    self.log_info('  sending logout request in HTTP POST')

    idp_params = self.context.idp_params
    app_params = self.context.last_app_params
    
    request = self.post_form.get('logout_request', '')
    relay_state = self.post_form.get('relay_state', '')

    self.log_info("Logout request:")
    self.log_info(request)

    byte_xml_req = request.encode()

    sign_logout_request = app_params.get('sign_logout_request', 'off')
    if Configuration.is_on(sign_logout_request):
    
      # Signature de la requête
      template = etree.fromstring(request)
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
      ref = xmlsec.template.add_reference(signature_node, xmlsec.Transform.SHA1, uri='#'+app_params['request_id'])
      xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
      xmlsec.template.add_transform(ref, xmlsec.constants.TransformExclC14N)
      key_info = xmlsec.template.ensure_key_info(signature_node)
      xmlsec.template.add_x509_data(key_info)  
      
      # Récupération des clés
      if app_params.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + app_params['sp_private_key'] + '\n-----END PRIVATE KEY-----'
      if app_params.get('sp_certificate', '') == '':
        raise AduneoError("Missing certificate, can't sign request")
      sp_certificate = '-----BEGIN CERTIFICATE-----\n' + app_params['sp_certificate'] + '\n-----END CERTIFICATE-----'

      # on signe le XML
      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      ctx.key.load_cert_from_memory(sp_certificate, xmlsec.KeyFormat.CERT_PEM)
      ctx.sign(signature_node)
      self.log_info('Signed request:')
      self.log_info(etree.tostring(template, pretty_print=True).decode())
      
      byte_xml_req = etree.tostring(template)
      
    base64_req = base64.b64encode(byte_xml_req).decode()
    self.log_info("Base64 encoded logout request:")
    self.log_info(base64_req)

    self.send_page_top(200, template=False)

    saml_form = """
      <html><body onload="document.saml.submit()">
      <form name="saml" action="{idp_slo_url}" method="post">
      <input type="hidden" name="SAMLRequest" value="{saml_request}" />
      <input type="hidden" name="RelayState" value="{relay_state}" />
      </form></body></html>
    """.format(idp_slo_url=idp_params['idp_slo_url'], saml_request=html.escape(base64_req), relay_state=html.escape(relay_state))

    self.log_info("SAML POST form:")
    self.log_info(saml_form)

    self.add_content(saml_form)


  def _send_request_redirect(self):
    """ Envoie la requête de déconnexion SAML en REDIRECT

    Versions:
      05/01/2025 (mpham) version initiale copiée d'OAuth 2 et de l'ancienne version de SAML
    """

    self.log_info('  sending logout request in HTTP POST')

    idp_params = self.context.idp_params
    app_params = self.context.last_app_params
    
    request = self.post_form.get('logout_request', '')
    relay_state = self.post_form.get('relay_state', '')

    self.log_info("Logout request:")
    self.log_info(request)
    
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
    deflated_req = compress.compress(request.encode('iso-8859-1'))
    deflated_req += compress.flush()
    
    base64_req = base64.b64encode(deflated_req)
    logging.info("Base64 encoded deflated logout request:")
    logging.info(base64_req.decode())
    
    urlencoded_req = urllib.parse.quote_plus(base64_req) # TODO vérifier que ce n'est pas quote plutôt que quote_plus
    
    # Signature de la requête
    #   on construit le message SAMLRequest=value&RelayState=value&SigAlg=value
    #   (les valeurs doivent être URL-encoded)
    #   que l'on signe
    
    urlencoded_relay_state = urllib.parse.quote_plus(relay_state)

    message = 'SAMLRequest='+urlencoded_req+'&RelayState='+urlencoded_relay_state
    
    sign_logout_request = app_params.get('sign_logout_request', 'off')
    if Configuration.is_on(sign_logout_request):
    
      urlencoded_sig_alg = urllib.parse.quote_plus('http://www.w3.org/2000/09/xmldsig#rsa-sha1')
      
      message += '&SigAlg='+urlencoded_sig_alg
      logging.info('Signature message: '+message)

      xmlsec.enable_debug_trace(True)

      if app_params.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + app_params['sp_private_key'] + '\n-----END PRIVATE KEY-----'

      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      signature = ctx.sign_binary(message.encode(), xmlsec.constants.TransformRsaSha1)
      base64_signature = base64.b64encode(signature).decode()
      logging.info('Signature: '+base64_signature)

      message += '&signature=' + urllib.parse.quote_plus(base64_signature)

    url = idp_params['idp_slo_url'] + '?' + message
    logging.info('URL: '+url)
    
    logging.info('Sending redirection')
    self.send_redirection(url)
    
    
  @register_page_url(url='callback', method=['GET','POST'], template='page_default.html', continuous=True)
  def callback(self):
    """ Retour de logout
    
    Versions:
      15/03/2021 (mpham) version initiale
      20/01/2023 (mpham) méthode HTTP-Redirect
      05/01/2025 (mpham) adaptation continuous page
    """

    logging.info('Logout call back')

    xml_resp = None
    relay_state = None
    
    if self.hreq.command == 'POST':

      # Problème cookie SameSite=Lax
      if self.hreq.headers.get('Cookie') is None:
        self.log_error('Session cookie not sent by brower (SameSite problem), form is sent to brower and autosubmitted')
      
        self.add_content('<html><body onload="document.saml.submit()">')
        self.add_content('<div>SameSite workaround, submitting response form from ClientFedID</div>')
        self.add_content('<form name="saml" method="post">')
        for item in self.post_form:
          self.add_content('<input type="hidden" name="'+html.escape(item)+'" value="'+html.escape(self.post_form[item])+'" />')
        #self.add_content('<input type="submit" />')
        self.add_content('</form></body></html>')
        return

      self.log_info(str(self.post_form))

      base64_resp = self.post_form.get('SAMLResponse', None)
      if base64_resp is None:
        raise AduneoError('SAMLResponse not found in POST data')
      xml_resp = base64.b64decode(base64_resp).decode()
      relay_state = self.post_form.get('RelayState')
      if not relay_state:
        raise AduneoError(self.log_error(f"Can't retrieve request context from state because state in not present in callback body {self.post_form}"))
      
    elif self.hreq.command == 'GET':
      
      quoted_resp = self.get_query_string_param('SAMLResponse')
      if quoted_resp is None:
        raise AduneoError('SAMLResponse not found in GET data')
      relay_state = self.get_query_string_param('RelayState')
      if not relay_state:
        raise AduneoError(self.log_error(f"Can't retrieve request context from state because state in not present in callback query string {self.hreq.path}"))
      
      # on dézippe la réponse
      base64_resp = urllib.parse.unquote(quoted_resp)
      compressed_resp = base64.b64decode(base64_resp)
      decompressed_resp = zlib.decompress(compressed_resp, -zlib.MAX_WBITS)
      xml_resp = decompressed_resp.decode('iso-8859-1')

    # récupération de state pour obtention des paramètres dans la session
    self.log_info('  for state: '+relay_state)

    context_id = self.get_session_value(relay_state)
    if not context_id:
      raise AduneoError(self.log_error(f"Can't retrieve request context from state because context id not found in session for state {relay_state}"))

    self.context = self.get_session_value(context_id)
    if not self.context:
      raise AduneoError(self.log_error(f"Can't retrieve request context because context id {context_id} not found in session"))

    self.log_info(xml_resp)

    root_el = etree.fromstring(xml_resp.encode())
    
    status_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status')
    status_code_el = status_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
    status_code = status_code_el.attrib['Value']
    self.log_info('Status code: '+status_code)

    self.add_html('<h2>Logout callback</h2>')
    self.add_html(status_code)
    self.add_menu()
    self.send_page()
    
    if status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success':
      sp_id = relay_state
      if sp_id is not None:
        self.log_info('Removing session for SP '+sp_id)
        self.logoff('saml_client_'+sp_id)

