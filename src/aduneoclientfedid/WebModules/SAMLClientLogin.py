"""
Copyright 2023-2025 Aduneo

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
import copy
import html
import json
import os
import time
import traceback
import urllib.parse
import uuid
import xmlsec
import zlib

from datetime import datetime
from lxml import etree
from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url, register_page_url
from ..CfiForm import CfiForm
from ..Configuration import Configuration
from ..Context import Context
from ..Help import Help
from .Clipboard import Clipboard
from .FlowHandler import FlowHandler
from .SAMLClientAdmin import SAMLClientAdmin


"""
  Un contexte de chaque cinématique est conservé dans la session.
    Ce contexte est compatible avec OpenID Connect et OAuth 2, afin de réaliser des échanges de jetons
    
    Ce contexte est indexé par un identifiant unique à la cinmatique, ce qui permet à un même ordinateur de suivre plusieurs cinématiques en parallèle
    Cet index est le state, que l'on récupère donc en retour d'IdP
    
    Le contexte en lui-même est composé d'une partie commune SAML/OIDC/OAuth et d'une partie spécifique SAML
    
    Contexte commun :
    "context_id": "<state (l'index de la session)>"
    "initial_flow": {
      "app_id": "<identifiant du client ClientFedID>",
      "flow_type": "SAML",
    }
    "tokens": {
      "saml_assertion": "<XML>",
      "access_token": "<access_token>",
      "id_token": "<id_token>"
    }
    
    Contexte spécifique :
    "request": {
      (éléments de la requête)
    }
    
"""

@register_web_module('/client/saml/login')
class SAMLClientLogin(FlowHandler):

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=False)
  def prepare_request(self):
    """
      Prépare la requête d'autorisation SAML

    Versions:
      02/01/2025 (mpham) version initiale copiée d'OAuth 2 et de l'ancienne version de SAML
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """

    self.log_info('--- Start SAML flow ---')

    try:

      idp_id = self.get_query_string_param('idpid')
      app_id = self.get_query_string_param('appid')

      fetch_configuration_document = False

      new_auth = True
      if self.context is None:
        if idp_id is None or app_id is None:
          raise AduneoError(f"Missing idpip or appid in URL", button_label="Homepage", action="/")
      else:
        new_auth = False
      
      if self.get_query_string_param('newauth'):
        new_auth = True

      if new_auth:
        # Nouvelle requête
        idp = copy.deepcopy(self.conf['idps'][idp_id])
        idp_params = idp['idp_parameters']
        saml_idp_params = idp_params.get('saml')
        if not saml_idp_params:
          raise AduneoError(f"SAML IdP parameters have not been defined for IdP {idp_id}", button_label="IdP parameters", action=f"/client/idp/admin/modify?idpid={idp_id}")
        
        app_params = idp['saml_clients'][app_id]

        # On récupère name des paramètres de l'IdP
        idp_params['name'] = idp['name']

        # si le contexte existe, on le conserve (cas newauth)
        if self.context is None:
          self.context = Context()
        self.context['idp_id'] = idp_id
        self.context['app_id'] = app_id
        self.context['flow_type'] = 'SAML'
        self.context['idp_params'] = idp_params
        self.context['app_params'][app_id] = app_params
        self.set_session_value(self.context['context_id'], self.context)

      else:
        # Rejeu de requête (conservée dans la session)
        idp_id = self.context['idp_id']
        app_id = self.context['app_id']
        idp_params = self.context.idp_params
        saml_idp_params = idp_params['saml']
        app_params = self.context.last_app_params
      
      self.log_info(('  ' * 1) + f"for SP {app_params['name']} of IdP {idp_params['name']}")
      self.add_html(f"<h1>IdP {idp_params['name']} SAML SP {app_params['name']}</h1>")
      
      relay_state = str(uuid.uuid4())

      # possibilités de SAML en binding
      idp_authentication_binding_capabilities = saml_idp_params.get('idp_authentication_binding_capabilities')
      if not idp_authentication_binding_capabilities:
        idp_authentication_binding_capabilities = self.conf.get('/default/saml/idp_authentication_binding_capabilities')
        if not idp_authentication_binding_capabilities:
          idp_authentication_binding_capabilities = ['urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']

      form_content = {
        'hr_context': self.context['context_id'],
        'name': app_params.get('name', ''),
        'idp_entity_id': saml_idp_params.get('idp_entity_id', ''),
        'idp_certificate': saml_idp_params.get('idp_certificate', ''),
        'idp_sso_url': saml_idp_params.get('idp_sso_url', ''),
        'sp_entity_id': app_params.get('sp_entity_id', ''),
        'sp_acs_url': app_params.get('sp_acs_url', ''),
        'nameid_policy': app_params.get('nameid_policy', 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'),
        'authentication_binding': app_params.get('authentication_binding', 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'),
        'sign_auth_request': Configuration.is_on(app_params.get('sign_auth_request', 'off')),
        'sp_private_key': '',
        'sp_certificate': app_params.get('sp_certificate', ''),
        'relay_state': relay_state,
        'request_id': 'id'+str(uuid.uuid4()),
        'authentication_request': '',
      }
      
      form = CfiForm('samlauth', form_content, action='/client/saml/login/sendrequest', mode='new_page') \
        .hidden('hr_context') \
        .hidden('name') \
        .hidden('request_id') \
        .start_section('idp_params', title="IdP parameters") \
          .text('idp_entity_id', label='IdP entity ID', clipboard_category='idp_entity_id') \
          .text('idp_sso_url', label='IdP SSO URL', clipboard_category='idp_sso_url', on_change='updateAuthenticationRequest(cfiForm)') \
          .textarea('idp_certificate', label='IdP certificate', rows=10, clipboard_category='idp_certificate', upload_button='Upload IdP certificate') \
        .end_section() \
        .start_section('sp_parameters', title="SP parameters") \
          .text('sp_entity_id', label='SP entity ID', clipboard_category='sp_entity_id', on_change='updateAuthenticationRequest(cfiForm)') \
          .text('sp_acs_url', label='SP Assertion Consumer Service URL', clipboard_category='sp_acs_url', on_change='updateAuthenticationRequest(cfiForm)') \
          .open_list('nameid_policy', label='NameID policy', clipboard_category='nameid_policy', on_change='updateAuthenticationRequest(cfiForm)', 
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
          .closed_list('authentication_binding', label='Authentication binding', on_change='updateAuthenticationRequest(cfiForm)',
            values = {value: value for value in idp_authentication_binding_capabilities},
            default = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            ) \
          .check_box('sign_auth_request', label='Sign authentication request') \
          .textarea('sp_private_key', label='SP private key', rows=10, clipboard_category='sp_private_key', upload_button='Upload SP private key', displayed_when="@[sign_auth_request]") \
          .textarea('sp_certificate', label='SP certificate', rows=10, clipboard_category='sp_certificate', upload_button='Upload SP certificate', displayed_when="@[sign_auth_request]") \
        .end_section() \
        .start_section('authn_params', title="Authentication request") \
          .text('relay_state', label='Relay state', clipboard_category='relay_state') \
          .textarea('authentication_request', label='SAML authentication request', rows=10, clipboard_category='authentication_request', upload_button='Upload XML', on_load='updateAuthenticationRequest(cfiForm)') \
        .end_section() \

      self.add_javascript_include('/javascript/SAMLClientLogin.js')
      self.add_html(form.get_html())
      self.add_javascript(form.get_javascript())

    except AduneoError as error:
      self.add_html('<h4>Error: '+html.escape(str(error))+'</h4>')
      self.add_html(f"""
        <div>
          <span><a class="middlebutton" href="{error.action}">{error.button_label}</a></span>
        </div>
        """)
    except Exception as error:
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Refresh error: '+html.escape(str(error))+'</h4>')
      

  @register_url(url='sendrequest', method='POST')
  def send_request(self):
    """
      Prépare la requête d'autorisation SAML

    Versions:
      02/01/2025 (mpham) version initiale copiée d'OAuth 2 et de l'ancienne version de SAML
      27/02/2025 (mpham) les paramètres IdP n'étaient pas mis à jour au bon endroit
    """

    try:
    
      if not self.context:
        self.log_error("""context_id not found in form data {data}""".format(data=self.post_form))
        raise AduneoError("Context not found in request")

      self.log_info('Redirection to SAML IdP requested')
      relay_state = self.post_form.get('relay_state', '')
      if relay_state == '':
        raise AduneoError("Relay state not found in request")
      self.log_info(f"  for relay state {relay_state}")

      # pour récupérer le contexte depuis le state (puisque c'est la seule information exploitable retournée par l'IdP)
      self.set_session_value(relay_state, self.context['context_id'])

      # Mise à jour dans le contexte des paramètres liés à l'IdP
      idp_params = self.context.idp_params
      saml_idp_params = idp_params['saml']
      for item in ['idp_entity_id', 'idp_certificate', 'idp_sso_url']:
        saml_idp_params[item] = self.post_form.get(item, '').strip()

      # Mise à jour dans le contexte des paramètres liés au client courant
      app_params = self.context.last_app_params
      for item in ['sp_entity_id', 'sp_acs_url', 'nameid_policy', 'authentication_binding', 'sp_private_key', 'sp_certificate', 'request_id']:
        app_params[item] = self.post_form.get(item, '').strip()
        
      if 'sign_auth_request' in self.post_form:
        app_params['sign_auth_request'] = 'on'
      else:
        app_params['sign_auth_request'] = 'off'

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

      # détermination de la méthode d'envoi à l'IdP
      authentication_binding = self.post_form.get('authentication_binding', '')
      self.log_info('  with binding '+authentication_binding)
      if authentication_binding == '':
        raise AduneoError("Authentication binding not found")
      if authentication_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect':
        self.send_request_redirect()
      elif authentication_binding == 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST':
        self.send_request_post()
      else:
        raise AduneoError(f"Authentication binding {authentication_binding} not supported")

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


  def send_request_redirect(self):
    """ Envoie la requête d'authentification en HTTP-Redirect
    
    Versions:
      00/00/2022 (mpham) version initiale
      03/03/2023 (mpham) le protocolBinding était à POST au lieu de Redirect dans la requête
      03/01/2025 (mpham) adaptation à CfiForm
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """
    
    self.log_info('  sending request in HTTP Redirect')

    idp_params = self.context.idp_params
    saml_idp_params = idp_params['saml']
    app_params = self.context.last_app_params
    
    request = self.post_form.get('authentication_request', '')
    relay_state = self.post_form.get('relay_state', '')
    
    self.log_info("Authentication request:")
    self.log_info(request)
    
    # on deflate la requête
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
    self.log_info("Base64 encoded deflated authentication request:")
    self.log_info(base64_req.decode())
    
    urlencoded_req = urllib.parse.quote_plus(base64_req)

    sign_auth_request = self.post_form.get('sign_auth_request', 'off')
    if Configuration.is_on(sign_auth_request):
    
      # Signature de la requête
      #   on construit le message SAMLRequest=value&RelayState=value&SigAlg=value
      #   (les valeurs doivent être URL-encoded)
      #   que l'on signe
      
      urlencoded_relay_state = urllib.parse.quote_plus(relay_state)
      urlencoded_sig_alg = urllib.parse.quote_plus('http://www.w3.org/2000/09/xmldsig#rsa-sha1')
      
      message = 'SAMLRequest='+urlencoded_req+'&RelayState='+urlencoded_relay_state+'&SigAlg='+urlencoded_sig_alg
      self.log_info('Signature message: '+message)

      xmlsec.enable_debug_trace(True)

      if app_params.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + app_params['sp_private_key'] + '\n-----END PRIVATE KEY-----'

      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      signature = ctx.sign_binary(message.encode(), xmlsec.constants.TransformRsaSha1)
      base64_signature = base64.b64encode(signature).decode()
      self.log_info('Signature: '+base64_signature)

      url = saml_idp_params['idp_sso_url'] + '?' + message + '&signature=' + urllib.parse.quote_plus(base64_signature)
      self.log_info('URL: '+url)
      self.log_info('Sending redirection')
      self.send_redirection(url)
      
    else:
      # requête non signée
    
      url = self.post_form['idp_sso_url'] + '?SAMLRequest=' + urlencoded_req + '&RelayState=' + urllib.parse.quote_plus(relay_state)
      self.log_info('URL: '+url)
      self.log_info('Sending redirection')
      
      self.send_redirection(url)


  def send_request_post(self):
    """ Envoie la requête d'authentification en HTTP-Redirect
    
    Versions:
      00/00/2022 (mpham) version initiale
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """

    self.log_info('  sending request in HTTP POST')
    
    idp_params = self.context.idp_params
    saml_idp_params = idp_params['saml']
    app_params = self.context.last_app_params
    
    request = self.post_form.get('authentication_request', '')
    relay_state = self.post_form.get('relay_state', '')
    
    self.log_info("Authentication request:")
    self.log_info(request)
    
    byte_xml_req = request.encode()

    sign_auth_request = self.post_form.get('sign_auth_request', 'off')
    if Configuration.is_on(sign_auth_request):
    
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

      # on signe le XML
      if app_params.get('sp_private_key', '') == '':
        raise AduneoError("Missing private key, can't sign request")
      sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + app_params['sp_private_key'] + '\n-----END PRIVATE KEY-----'
      if self.post_form.get('sp_certificate', '') == '':
        raise AduneoError("Missing certificate, can't sign request")
      sp_certificate = '-----BEGIN CERTIFICATE-----\n' + app_params['sp_certificate'] + '\n-----END CERTIFICATE-----'

      ctx = xmlsec.SignatureContext()
      ctx.key = xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None)
      ctx.key.load_cert_from_memory(sp_certificate, xmlsec.KeyFormat.CERT_PEM)
      ctx.sign(signature_node)
      self.log_info('Signed request:')
      self.log_info(etree.tostring(template, pretty_print=True).decode())
      
      byte_xml_req = etree.tostring(template)
      
    base64_req = base64.b64encode(byte_xml_req).decode()
    self.log_info("Base64 encoded authentication request:")
    self.log_info(base64_req)

    self.send_page_top(200, template=False)
    
    saml_form = """
      <html><body onload="document.saml.submit()">
      <form name="saml" action="{idp_sso_url}" method="post">
      <input type="hidden" name="SAMLRequest" value="{saml_request}" />
      <input type="hidden" name="RelayState" value="{relay_state}" />
      </form></body></html>
    """.format(idp_sso_url=saml_idp_params['idp_sso_url'], saml_request=html.escape(base64_req), relay_state=html.escape(relay_state))
    
    self.log_info("SAML POST form:")
    self.log_info(saml_form)

    self.add_content(saml_form)

    
  @register_page_url(url='acs', method='POST', template='page_default.html', continuous=True)
  def authcallback(self):
    """
    Retour d'authentification (endpoint ACS)
    
    Problème Chrome et "SameSite by default"
    
    Chrome bloque parfois le cookie de session en retour SAML parce qu'il considère le cookie en Lax par défaut.
    De ce fait, lorsque l'IdP poste sa réponse, elle arrive d'un autre site que celui du client (souvent localhost)
    et Chrome n'envoie pas le cookie de session.
    
    Parfois, ça fonctionne quand même, je n'ai pas encore compris pourquoi.
    
    Une description par Okta : https://support.okta.com/help/s/article/FAQ-How-Chrome-80-Update-for-SameSite-by-default-Potentially-Impacts-Your-Okta-Environment?language=en_US
    Une discussion StackOverflow : https://stackoverflow.com/questions/60068271/samesite-attribute-break-saml-flow
    
    Il faudrait donc passer en SameSite=None pour autoriser que le cookie de session soit envoyé depuis l'IdP
    Mais ça requiert HTTPS (ne fonctionne donc pas en HTTP)
    
    On résout le problème en renvoyant un formulaire au navigateur avec un autosubmit :
      les informations proviennent du client et tout rentre dans l'ordre
      (il faut cependant faire attention à ne pas créer une nouvelle session, voir Server.do_POST)
    
    Versions:
      03/03/2021-05/03/2021 (mpham) version initiale
      28/02/2023 (mpham) le bouton de copie n'est pas affiché pour les résultats de type 'passed'
      03/01/2025 (mpham) adaptation continuous page
      27/02/2025 (mpham) les paramètres IdP n'étaient pas récupérés du bon endroit
    """
    
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

    self.add_javascript_include('/javascript/resultTable.js')
    self.add_javascript_include('/javascript/clipboard.js')
    try:

      self.log_info('SAML Authentication callback')
      self.log_info('  raw response:')
      self.log_info('  '+str(self.post_form))
      
      warnings = []

      # récupération de state pour obtention des paramètres dans la session
      idp_relay_state = self.post_form.get('RelayState', None)
      if idp_relay_state is None:
        raise AduneoError(f"Can't retrieve request context from relay state because state in not present in callback POST data")
      self.log_info('  SAML callback for state: '+idp_relay_state)

      context_id = self.get_session_value(idp_relay_state)
      if not context_id:
        raise AduneoError(f"Can't retrieve request context from state because context id not found in session for state {idp_relay_state}")

      self.context = self.get_session_value(context_id)
      if not self.context:
        raise AduneoError(f"Can't retrieve request context because context id {context_id} not found in session")
      
      # extraction des informations utiles de la session
      idp_id = self.context.idp_id
      app_id = self.context.app_id
      idp_params = self.context.idp_params
      saml_idp_params = idp_params['saml']
      app_params = self.context.last_app_params

      self.add_html(f"<h3>SAML callback from {html.escape(idp_params['name'])} for client {html.escape(app_params['name'])}</h3>")

      self.start_result_table()
      self.add_result_row('Relay state returned by IdP', idp_relay_state, 'idp_relay_state')
      
      self.add_result_row('Raw response', str(self.post_form), 'idp_raw_response')

      # analyse du XML de réponse
      base64_resp = self.post_form.get('SAMLResponse', None)
      if base64_resp is None:
        raise AduneoError('SAMLResponse not found in POST data')
      xml_resp = base64.b64decode(base64_resp).decode()

      self.log_info(xml_resp)

      root_el = etree.fromstring(xml_resp.encode())
      self.add_result_row('XML response', etree.tostring(root_el, pretty_print=True).decode(), 'xml_response')
      
      # Vérification du statut
      try:
        status_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}Status')
        if status_el is None:
          raise AduneoError('Status element not found')
        status_code_el = status_el.find('{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode')
        if status_code_el is None:
          raise AduneoError('StatusCode element not found')
        status_code = status_code_el.attrib['Value']
        self.log_info('Status code: '+status_code)
        
        if status_code == 'urn:oasis:names:tc:SAML:2.0:status:Success':
          self.add_result_row('Status authenticated', status_code, 'status_code')
        else:
          self.add_result_row('Status failed', status_code, 'status_code')
          raise AduneoError('wrong status: '+status_code)
        
      except Exception as error:
        self.log_error("Status verification failed: "+str(error))
        raise AduneoError('status verification failed: '+str(error))
        
      # Vérification d'issuer
      self.log_info('Issuer verification')
      try:
        issuer_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
        if issuer_el is None:
          raise AduneoError('Issuer element not found')
        issuer = issuer_el.text
        self.log_info('issuer       : '+issuer)
        self.log_info('IdP entity id: '+saml_idp_params['idp_entity_id'])
        
        if issuer == saml_idp_params['idp_entity_id']:
          self.add_result_row('Issuer verification passed', issuer, 'issuer_verification')
        else:
          title = 'Issuer verification failed'
          value = issuer+' (response) != '+saml_idp_params['idp_entity_id']+' (conf)'
          self.add_result_row(title, value, 'issuer_verification')
          raise AduneoError(title)
        
      except Exception as error:
        self.log_error("Issuer verification failed: "+str(error))
        raise AduneoError('issuer verification failed: '+str(error))

      # Vérification de signature de la réponse
      self.log_info('Response signature verification')
      try:
        self.log_info('IdP Certificate')
        self.log_info(saml_idp_params['idp_certificate'])
      
        cert = '-----BEGIN CERTIFICATE-----\n' + saml_idp_params['idp_certificate'] + '\n-----END CERTIFICATE-----'
      
        xmlsec.enable_debug_trace(True)
        xmlsec.tree.add_ids(root_el, ["ID"]) # -> correspond à l'attribut ID dans le tag response, c'est demandé par XML Signature
        # Référence : https://www.aleksey.com/xmlsec/faq.html (section 3.2) : LibXML2 and XMLSec libraries do support ID attributes. However, you have to tell LibXML2/XMLSec what is the name of your ID attribute. XML specification does not require ID attribute to have name "Id" or "id". It can be anything you want!
        # Ca permet à XMLSec de faire le lien entre la signature et le contenu. Dans la signature, il y a une référence par URI="# à la reponse au travers d'un identifiant unique. Il faut indiquer que la recherche du contenu se fait apr le tag ID
        signature_node = xmlsec.tree.find_node(root_el, xmlsec.constants.NodeSignature)
        
        manager = xmlsec.KeysManager()
        manager.load_cert_from_memory(cert, xmlsec.constants.KeyDataFormatPem, xmlsec.KeyDataType.TRUSTED)
        ctx = xmlsec.SignatureContext(manager)
        ctx.verify(signature_node)
        self.log_info('Response signature verification: OK')
        self.add_result_row('Response signature verification', 'Passed', 'response_signature_verification', copy_button=False)
      
      except Exception as error:
        self.log_error("Response signature verification failed: "+str(error))
        self.add_result_row('Response signature failed', str(error), 'response_signature_verification')
        raise AduneoError('Response signature verification failed: '+str(error))

      # Extraction de l'assertion
      self.log_info('Extracting assertion')
      assertion_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
      if assertion_el is None:
        # on ne trouve pas l'assertion directement, elle est peut-être chiffrée
        self.log_info('Element Assertion not found, looking for EncryptedAssertion')
        
        encrypted_assertion_el = root_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}EncryptedAssertion')
        if encrypted_assertion_el is None:
          raise AduneoError('Neither Assertion nor EncryptedAssertion elements found')

        self.log_info('EncryptedAssertion')
        self.log_info(etree.tostring(encrypted_assertion_el).decode())
        
        xmlsec.tree.add_ids(encrypted_assertion_el, ["Id"]) # attention, on est case sensitive !
        
        sp_private_key = '-----BEGIN PRIVATE KEY-----\n' + app_params['sp_private_key'] + '\n-----END PRIVATE KEY-----'
        
        manager = xmlsec.KeysManager()
#        manager.add_key(xmlsec.Key.from_file('conf/localhost.key', xmlsec.KeyFormat.PEM, None))
        manager.add_key(xmlsec.Key.from_memory(sp_private_key, xmlsec.KeyFormat.PEM, None))
        enc_ctx = xmlsec.EncryptionContext(manager)
        enc_data = xmlsec.tree.find_child(encrypted_assertion_el, "EncryptedData", xmlsec.constants.EncNs)
        assertion_el = enc_ctx.decrypt(enc_data)
        self.log_info('Assertion decrypted')
        self.add_result_row('Assertion decryption', 'OK')
      
      self.log_info('XML assertion')
      self.log_info(etree.tostring(assertion_el).decode())
      self.add_result_row('XML assertion', etree.tostring(assertion_el, pretty_print=True).decode(), 'assertion')

      # Extraction des conditions de validité de l'assertion
      conditions_el = assertion_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}Conditions')
      if conditions_el is None:
        raise AduneoError('Conditions element not found')
      
      # Vérification de timestamp
      now = datetime.utcnow()
      
      self.log_info("NotBefore condition verification:")
      not_before_str = conditions_el.attrib.get('NotBefore')
      if not_before_str is None:
        raise AduneoError('NotBefore attribute not found')
      self.log_info('NotBefore attribute: '+not_before_str)
      
      #not_before_date = datetime.strptime(not_before_str, '%Y-%m-%dT%H:%M:%S.%fZ')
      not_before_date = self._parse_saml_date(not_before_str)
      self.log_info("Assertion NotBefore: "+str(not_before_date)+' UTC')
      self.log_info("Now                : "+str(now)+' UTC')
      if now > not_before_date:
        self.log_info("NotBefore condition verification OK")
        self.add_result_row('NotBefore condition passed', str(not_before_date)+' UTC (now is '+str(now)+' UTC)', 'notbefore_verification')
      else:
        self.log_info("NotBefore condition verification failed")
        self.add_result_row('NotBefore condition failed', str(not_before_date)+' UTC (now is '+str(now)+' UTC)', 'notbefore_verification')
        raise AduneoError('NotBefore condition failed')
        
      self.log_info("NotOnOrAfter condition verification:")
      not_on_or_after_str = conditions_el.attrib.get('NotOnOrAfter')
      if not_on_or_after_str is None:
        raise AduneoError('NotOnOrAfter attribute not found')
      self.log_info('NotOnOrAfter attribute: '+not_on_or_after_str)
      
      not_on_or_after_date = self._parse_saml_date(not_on_or_after_str)
      self.log_info("Assertion NotOnOrAfter: "+str(not_on_or_after_date)+' UTC')
      self.log_info("Now                : "+str(now)+' UTC')
      if now < not_on_or_after_date:
        self.log_info("NotOnOrAfter condition verification OK")
        self.add_result_row('NotOnOrAfter condition passed', str(not_on_or_after_date)+' UTC (now is '+str(now)+' UTC)', 'notonorafter_verification')
      else:
        self.log_info("NotOnOrAfter condition verification failed")
        self.add_result_row('NotOnOrAfter condition failed', str(not_on_or_after_date)+' UTC (now is '+str(now)+' UTC)', 'notonorafter_verification')
        raise AduneoError('NotOnOrAfter condition failed')
      
      # Vérification d'audience
      self.log_info("Audience condition verification:")
      
      audience_restriction_el = conditions_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction')
      if audience_restriction_el is None:
        raise AduneoError('AudienceRestriction element not found')
      audience_el = audience_restriction_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}Audience')
      if audience_el is None:
        raise AduneoError('Audience element not found')
      audience = audience_el.text
      self.log_info("Audience    : "+audience)
      self.log_info("SP Entity ID: "+app_params['sp_entity_id'])
      if audience == app_params['sp_entity_id']:
        self.log_info("Audience condition OK")
        self.add_result_row('Audience condition passed', audience, 'audience_verification')
      else:
        self.log_info("Audience condition failed")
        title = 'Audience condition failed'
        value = audience+' (response) != '+app_params['sp_entity_id']+' (conf)'
        self.add_result_row(title, value, 'audience_verification')
        raise AduneoError(title)
      
      # Vérification de signature de l'assertion
      self.log_info('Assertion signature verification')
      try:
        self.log_info('IdP Certificate')
        self.log_info(saml_idp_params['idp_certificate'])
      
        cert = '-----BEGIN CERTIFICATE-----\n' + saml_idp_params['idp_certificate'] + '\n-----END CERTIFICATE-----'
      
        xmlsec.enable_debug_trace(True)
        xmlsec.tree.add_ids(assertion_el, ["ID"]) # -> correspond à l'attribut ID dans le tag response, c'est demandé par XML Signature
        # Référence : https://www.aleksey.com/xmlsec/faq.html (section 3.2) : LibXML2 and XMLSec libraries do support ID attributes. However, you have to tell LibXML2/XMLSec what is the name of your ID attribute. XML specification does not require ID attribute to have name "Id" or "id". It can be anything you want!
        # Ca permet à XMLSec de faire le lien entre la signature et le contenu. Dans la signature, il y a une référence par URI="# à la reponse au travers d'un identifiant unique. Il faut indiquer que la recherche du contenu se fait apr le tag ID
        signature_node = xmlsec.tree.find_node(assertion_el, xmlsec.constants.NodeSignature)
        
        if signature_node:
        
          manager = xmlsec.KeysManager()
          manager.load_cert_from_memory(cert, xmlsec.constants.KeyDataFormatPem, xmlsec.KeyDataType.TRUSTED)
          ctx = xmlsec.SignatureContext(manager)
          ctx.verify(signature_node)
          self.log_info('Assertion signature verification: OK')
          self.add_result_row('Assertion signature verification', 'Passed', 'assertion_signature_verification', copy_button=False)
          
        else:

          self.log_info('Signature not found in assertion')
          self.add_result_row('Assertion signature verification', 'Warning: signature not found in assertion', 'assertion_signature_verification', copy_button=False)
          warnings.append('Signature not found in assertion')
      
      except Exception as error:
        self.log_error("Assertion signature verification failed: "+str(error))
        self.add_result_row('Assertion signature failed', str(error), 'assertion_signature_verification')
        print(traceback.format_exc())
        raise AduneoError('Assertion signature verification failed: '+str(error))

      
      # Extraction du subject
      self.log_info('Subject parsing')
      subject_el = assertion_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}Subject')
      if subject_el is None:
        self.log_info('Subject element not found in assertion')
        self.add_result_row('Subject', 'Not found in assertion')
        raise AduneoError('Subject element not found in assertion')
        
      # Récupération du NameID
      nameid_el = subject_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}NameID')
      if nameid_el is None:
        self.log_info('NameID element not found in subject')
        self.add_result_row('NameID', 'Not found in subject')
        raise AduneoError('NameID element not found in subject')
        
      name_id = nameid_el.text
      self.log_info('NameID: '+name_id)
      self.add_result_row('NameID', name_id, 'name_id')
      
      name_id_format = nameid_el.attrib.get('Format', 'unspecified')
      self.log_info('NameID format: '+name_id_format)
      self.add_result_row('NameID format', name_id_format, 'name_id_format')
          
      # Validation du subject
      subjectconfirmation_el = subject_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmation')
      if subjectconfirmation_el is None:
        self.log_info('SubjectConfirmation element not found in subject')
        self.add_result_row('SubjectConfirmation', 'Not found in subject')
        raise AduneoError('SubjectConfirmation element not found in subject')
      
      subjectconfirmationdata_el = subjectconfirmation_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData')
      if subjectconfirmationdata_el is None:
        self.log_info('SubjectConfirmationData element not found in SubjectConfirmation')
        self.add_result_row('SubjectConfirmation', 'Not found in SubjectConfirmation')
        raise AduneoError('SubjectConfirmation element not found in SubjectConfirmation')
      
      # Vérification de l'identifiant de la requête
      in_response_to = subjectconfirmationdata_el.attrib.get('InResponseTo')
      if in_response_to is not None:
        self.log_info('Subject InResponseTo verification')
        self.log_info("InResponseTo: "+in_response_to)
        self.log_info("Request ID  : "+app_params['request_id'])
        if in_response_to == app_params['request_id']:
          self.log_info("Subject InResponseTo verification passed")
          self.add_result_row('Subject InResponseTo verification passed', in_response_to, 'inresponseto_verification')
        else:
          self.log_info("Subject InResponseTo verification failed")
          title = 'Subject InResponseTo verification failed'
          value = in_response_to+' (response) != '+app_params['request_id']+' (authn request)'
          self.add_result_row(title, value, 'inresponseto_verification')
          raise AduneoError(title)
      
      # Vérification du destinataire
      recipient = subjectconfirmationdata_el.attrib.get('Recipient')
      if recipient is not None:
        self.log_info('Subject Recipient verification')
        self.log_info("Recipient : "+recipient)
        self.log_info("SP ACS URL: "+app_params['sp_acs_url'])
        if recipient == app_params['sp_acs_url']:
          self.log_info("Subject Recipient verification passed")
          self.add_result_row('Subject Recipient verification passed', recipient, 'subject_recipient_verification')
        else:
          self.log_info("Subject Recipient verification failed")
          title = 'Subject Recipient verification failed'
          value = recipient+' (response) != '+app_params['sp_acs_url']+' (SP ACS URL)'
          self.add_result_row(title, value, 'subject_recipient_verification')
          raise AduneoError(title)

      # Vérification d'expiration (NotOnOrAfter)
      not_on_or_after_str = subjectconfirmationdata_el.attrib.get('NotOnOrAfter')
      if not_before_str is not None:
        self.log_info('Subject NotOnOrAfter verification')
        not_on_or_after_date = self._parse_saml_date(not_on_or_after_str)
        if now < not_on_or_after_date:
          self.log_info("Subject NotOnOrAfter verification passed")
          self.add_result_row('Subject NotOnOrAfter verification passed', str(not_on_or_after_date)+' UTC (now is '+str(now)+' UTC)', 'subject_notonorafter_verification')
        else:
          self.log_info("Subject NotOnOrAfter verification failed")
          title = 'Subject NotOnOrAfter verification failed'
          value = str(not_on_or_after_date)+' UTC (now is '+str(now)+' UTC)'
          self.add_result_row(title, value, 'subject_notonorafter_verification')
          raise AduneoError(title)
      
      # Extraction de SessionIndex
      self.log_info('Extracting AuthnStatement for SessionIndex')
      authn_statement_el = assertion_el.find('{urn:oasis:names:tc:SAML:2.0:assertion}AuthnStatement')
      if authn_statement_el is None:
        self.log_info('AuthnStatement element not found in assertion')
        self.add_result_row('AuthnStatement', 'Not found in assertion')
        raise AduneoError('AuthnStatement element not found in assertion')
      session_index = authn_statement_el.attrib.get('SessionIndex', '')
      self.log_info("SessionIndex: "+session_index)
      self.add_result_row('SessionIndex', session_index, 'session_index')
      
      self.end_result_table()
      self.add_html('<h3>Authentication successful</h3>')
      if len(warnings)>0:
        self.add_html('With warnings:')
        self.add_html('<ul>')
        for warning in warnings:
          self.add_html('<li>'+html.escape(warning)+'</li>')
        self.add_html('</ul>')
        
      # enregistrement de l'assertion dans la session pour manipulation ultérieure (échange contre un jeton OAuth 2)
      #   les assertions sont indexés par timestamp d'obtention
      assertion_name = 'Authn SAML '+app_params['name']+' - '+time.strftime("%H:%M:%S", time.localtime())
      assertion_wrapper = {'name': assertion_name, 'type': 'saml_assertion', 'app_id': app_id, 'saml_assertion': etree.tostring(assertion_el).decode(),
        'name_id': name_id, 'name_id_format': name_id_format, 'session_index': session_index}
      self.context['saml_assertions'][str(time.time())] = assertion_wrapper

      # on considère qu'on est bien loggé
      #   on place dans la session le NameID, son format et le SessionIndex, utilisés ensuite pour le logout (notice : on va maintenant chercher les infos de logout dans le contexte)
      self.logon('saml_client_'+idp_id+'/'+app_id, 
        {'NameID': name_id, 'Format': nameid_el.attrib.get('Format'), 'SessionIndex': session_index})

    except AduneoError as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')
      if error.explanation_code:
        self.add_html(Explanation.get(error.explanation_code))
    except Exception as error:
      if self.is_result_in_table():
        self.end_result_table()
      self.log_error(('  ' * 1)+traceback.format_exc())
      self.add_html('<h4>Authorization failed: '+html.escape(str(error))+'</h4>')

    self.log_info('--- End SAML flow ---')

    self.add_menu() 

    self.send_page()


  def _parse_saml_date(self, date_str:str) -> datetime:
    """Parse une date SAML, au format YYYY-MM-DD:hh:mm:ssZ
      Certains IdP mettent des millisecondes
    
      args:
        date_str: date au format YYYY-MM-DD:hh:mm:ssZ ou au format YYYY-MM-DD:hh:mm:ss.mmZ
        
      returns:
        objet datetime
        
      mpham 19/11/2022
    """
    
    if '.' in date_str:
      date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S.%fZ')
    else:
      date = datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%SZ')

    return date
