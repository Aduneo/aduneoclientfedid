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

import html
import json
import urllib
import uuid

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_page_url
from ..CfiForm import CfiForm, RequesterForm
from ..Configuration import Configuration


@register_web_module('/test')
class WebTest(BaseHandler):

  @register_page_url(url='', method='GET', template='page_default.html')
  def main(self):
    
    self.add_html('<base href="/test/" />')
    self.add_html('<a href="form">Formulaire simple</a><br>')
    self.add_html('<a href="cfiform">Formulaire CFI</a><br>')
    self.add_html('<a href="requesterform">Requêteur HTTP CFI</a><br>')
    self.add_html('<a href="oidcadmin">Administration OIDC</a><br>')
    self.add_html('<a href="oidcauth">Authentification OIDC</a><br>')
    self.add_html('<a href="oidcauth?id=azureadaduneo">Authentification OIDC pour Entra ID</a><br>')
    self.add_html('<a href="oidccallback">Callback OIDC</a><br>')
    self.add_html('<a href="listonchange">Closed list on change</a><br>')
    self.add_html('<a href="textonload">Text on load</a><br>')
    self.add_html('<a href="datagenerator">Request Data Generator</a><br>')
    self.add_html('<a href="tables">Tables</a><br>')
    self.add_html('<a href="openlisthtml">Open List Field HTML</a><br>')
    self.add_html('<a href="openlistcfiform">Open List Field CfiForm</a><br>')
    self.add_html('<a href="uploadbutton">Upload button</a><br>')
    self.add_html('<a href="noncontinuous">Page non continue</a><br>')


  @register_page_url(url='cfiform', method='GET', template='page_default.html')
  def cfiform(self):
    
    form_content = {
      'authorization_endpoint': 'https://aduneo.com/clientfedid/authorization_endpoint',
      'token_endpoint': 'https://aduneo.com/clientfedid/token_endpoint',
      'endpoint_configuration': 'discovery_uri',
      'signature_key_configuration': 'local_configuration',
      'verify_certificates': True,
      }
    
    form = CfiForm('oidcadmin', form_content, action='cfiformaction') \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name') \
        .text('redirect_uri', label='Redirect URI', help_button=False,
          on_load="init_url_with_domain({inputItem}, '/client/oidc/login/callback')"
          ) \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
      .end_section() \
      .start_section('section_from_op', title="Parameters obtained from OP") \
        .text('discovery_uri', label='Discovery URI', displayed_when="@[endpoint_configuration] = 'discovery_uri'") \
        .text('issuer', label='Issuer', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('authorization_endpoint', label='Authorization Endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token Endpoint', help_button=False, displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .closed_list('signature_key_configuration', label='Signature key configuration', displayed_when="@[endpoint_configuration] = 'local_configuration'",
          values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
          default = 'jwks_uri'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'jwks_uri'") \
        .text('signature_key', label='Signature key', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('section_logout', title="Logout configuration (optional)") \
        .start_section('section_logout_from_op', title="Logout information provided by OP", level=2) \
          .text('logout_endpoint', label='Logout endpoint') \
        .end_section() \
      .end_section() \
      .start_section('section_options', title="Options") \
      .end_section() \

    #.checkbox('verify_certificates', label='Verify certificates') \

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())

  @register_page_url(url='cfiformaction', method='POST', template='page_default.html')
  def cfiform_action(self):
    self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre><a href="cfiform">Retry</a>')


  @register_page_url(url='requesterform', method='GET', template='page_default.html', continuous=True)
  def requesterform(self):

    form_content = {
      'name': 'Authentification OpenID Connect',
      'authorization_endpoint': 'https://aduneo.com/clientfedid/authorization_endpoint',
      'token_endpoint': 'https://aduneo.com/clientfedid/token_endpoint',
      'scope': 'openid profile',
      'endpoint_configuration': 'discovery_uri',
      'signature_key_configuration': 'local_configuration',
      'token_endpoint_auth_method': 'Token endpoint auth scheme',
      'verify_certificates': True,
      'client_id': 'mylogin',
      'client_secret': 'mypassword',
      }
    
    form = RequesterForm('oidclogin', form_content, action='/test/requesterform_sender', request_url='@token_endpoint') \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name', readonly=True) \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri', help_button=False) \
        .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
      .end_section() \
      .start_section('section_from_op', title="Parameters obtained from OP") \
        .text('discovery_uri', label='Discovery URI', displayed_when="@[endpoint_configuration] = 'discovery_uri'") \
        .text('issuer', label='Issuer', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('authorization_endpoint', label='Authorization Endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token Endpoint', help_button=False, displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .closed_list('signature_key_configuration', label='Signature key configuration', displayed_when="@[endpoint_configuration] = 'local_configuration'",
          values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
          default = 'jwks_uri'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'jwks_uri'") \
        .text('signature_key', label='Signature key', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('section_logout', title="Logout configuration (optional)") \
        .start_section('section_logout_from_op', title="Logout information provided by OP", level=2) \
          .text('logout_endpoint', label='Logout endpoint') \
          .text('client_id', label='Client secret') \
          .password('client_secret', label='Client secret') \
        .end_section() \
      .end_section() \
      .start_section('section_options', title="Options") \
        .raw_html('<div>Options OpenID Connect</div><br>') \
        .textarea('notes', label='Notes', rows=3) \
      .end_section() \
      
    form.set_title('Authentification OpenID Connect')
    form.set_request_parameters({
        'scope': '@[scope]',
        'redirect_uri': '@[redirect_uri]',
        'client_secret': '@[client_secret]',
      })
    form.modify_http_parameters({
      'request_url': '@[discovery_uri]',
      'form_method': 'get',
      'body_format': 'x-www-form-urlencoded',
      'auth_method': 'form',
      'auth_login': '@[client_id]',
      'auth_secret': '@[client_secret]',
      'auth_login_param': 'client_id',
      'auth_secret_param': 'client_secret',
      'verify_certificates': True,
      })
    form.modify_visible_requester_fields({
      'request_url': True,
      'request_data': True,
      'form_method': True,
      'auth_method': True,
      'verify_certificates': True,
      })
    form.set_option('/clipboard/remember_secrets', True)
    form.set_option('/requester/auth_method_options', ['none', 'basic', 'form'])
    form.set_option('/requester/include_empty_items', False)
      

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())


  @register_page_url(url='requesterform_sender', method='POST', template='page_default.html')
  def requesterform_sender(self):
    self.add_html('<pre>'+json.dumps(self.post_form, indent=2)+'</pre><a href="requesterform">Retry</a>')


  @register_page_url(url='oidcadmin', method='GET', template='page_default.html', continuous=True)
  def oidc_admin(self):

    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id != '':
      rp = self.conf['oidc_clients'][rp_id]


    form_content = {
      'name': rp.get('name', ''),
      'endpoint_configuration': rp.get('endpoint_configuration', 'discovery_uri'),
      'discovery_uri': rp.get('discovery_uri', ''),
      'authorization_endpoint': rp.get('', ''),
      'token_endpoint': rp.get('', ''),
      'userinfo_endpoint': rp.get('userinfo_endpoint', ''),
      'logout_endpoint': rp.get('logout_endpoint', ''),
      'issuer': rp.get('issuer', ''),
      'signature_key_configuration': rp.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': rp.get('jwks_uri', ''),
      'signature_key': rp.get('signature_key', ''),
      'redirect_uri': rp.get('redirect_uri', ''),
      'post_logout_redirect_uri': rp.get('post_logout_redirect_uri', ''),
      'client_id': rp.get('client_id', ''),
      'scope': rp.get('scope', 'openid'),
      'response_type': rp.get('response_type', 'code'),
      'token_endpoint_auth_method': rp.get('token_endpoint_auth_method', 'client_secret_basic'),
      'verify_certificates': Configuration.is_on(rp.get('verify_certificates', 'on')),
      }
    
    form = CfiForm('oidcauth', form_content, action='/test/form', submit_label='Save') \
      .text('name', label='Name') \
      .start_section('op_endpoints', title="OP endpoints", collapsible=True, collapsible_default=False) \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
        .text('discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[endpoint_configuration] = 'discovery_uri'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('id_token_validation', title="ID token validation", collapsible=True, collapsible_default=True) \
        .text('issuer', label='Issuer', clipboard_category='issuer') \
        .closed_list('signature_key_configuration', label='Signature key configuration', displayed_when="@[endpoint_configuration] = 'local_configuration'",
          values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
          default = 'jwks_uri'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'jwks_uri'") \
        .text('signature_key', label='Signature key', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('rp_endpoints', title="OP endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri', help_button=False,
          on_load="init_url_with_domain({inputItem}, '/client/oidc/login/callback');"
          ) \
        .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri', help_button=False,
          on_load="init_url_with_domain({inputItem}, '/client/oidc/logout/callback');"
          ) \
      .end_section() \
      .start_section('openid_connect_configuration', title="OpenID Connect Configuration") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
        .closed_list('response_type', label='Reponse type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_option('/clipboard/remember_secrets', True)

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())




  @register_page_url(url='oidcauth', method='GET', template='page_default.html', continuous=True)
  def oidc_auth(self):

    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id != '':
      rp = self.conf['oidc_clients'][rp_id]


    form_content = {
      'name': rp.get('name', ''),
      'endpoint_configuration': rp.get('endpoint_configuration', 'discovery_uri'),
      'discovery_uri': rp.get('discovery_uri', ''),
      'authorization_endpoint': rp.get('', ''),
      'token_endpoint': rp.get('', ''),
      'userinfo_endpoint': rp.get('userinfo_endpoint', ''),
      'logout_endpoint': rp.get('logout_endpoint', ''),
      'issuer': rp.get('issuer', ''),
      'signature_key_configuration': rp.get('signature_key_configuration', 'jwks_uri'),
      'jwks_uri': rp.get('jwks_uri', ''),
      'signature_key': rp.get('signature_key', ''),
      'redirect_uri': rp.get('redirect_uri', ''),
      'post_logout_redirect_uri': rp.get('post_logout_redirect_uri', ''),
      'client_id': rp.get('client_id', ''),
      'scope': rp.get('scope', 'openid'),
      'response_type': rp.get('response_type', 'code'),
      'token_endpoint_auth_method': rp.get('token_endpoint_auth_method', 'client_secret_basic'),
      'verify_certificates': Configuration.is_on(rp.get('verify_certificates', 'on')),
      }
    
    form = RequesterForm('oidcauth', form_content, action='/test/requesterform_sender', request_url='@[authorization_endpoint]') \
      .text('name', label='Name') \
      .start_section('op_endpoints', title="OP endpoints") \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
        .text('discovery_uri', label='Discovery URI', clipboard_category='discovery_uri', displayed_when="@[endpoint_configuration] = 'discovery_uri'") \
        .text('authorization_endpoint', label='Authorization endpoint', clipboard_category='authorization_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
        .text('logout_endpoint', label='Logout endpoint', clipboard_category='logout_endpoint', displayed_when="@[endpoint_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('id_token_validation', title="ID token validation") \
        .text('issuer', label='Issuer', clipboard_category='issuer') \
        .closed_list('signature_key_configuration', label='Signature key configuration', displayed_when="@[endpoint_configuration] = 'local_configuration'",
          values = {'jwks_uri': 'JWKS URI', 'local_configuration': 'Local configuration'},
          default = 'jwks_uri'
          ) \
        .text('jwks_uri', label='JWKS URI', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'jwks_uri'") \
        .text('signature_key', label='Signature key', displayed_when="@[endpoint_configuration] = 'local_configuration' and @[signature_key_configuration] = 'local_configuration'") \
      .end_section() \
      .start_section('rp_endpoints', title="OP endpoints") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri', help_button=False) \
        .text('post_logout_redirect_uri', label='Post logout redirect URI', clipboard_category='post_logout_redirect_uri', help_button=False) \
      .end_section() \
      .start_section('openid_connect_configuration', title="OpenID Connect Configuration") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
        .closed_list('response_type', label='Reponse type', 
          values={'code': 'code'},
          default = 'code'
          ) \
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth scheme', 
          values={'none': 'none', 'client_secret_basic': 'client_secret_basic', 'client_secret_post': 'client_secret_post'},
          default = 'client_secret_basic'
          ) \
        .password('client_secret', label='Client secret', clipboard_category='client_secret!', displayed_when="@[token_endpoint_auth_method] = 'client_secret_basic' or @[token_endpoint_auth_method] = 'client_secret_post'") \
      .end_section() \
      .start_section('connection_options', title="Connection options") \
        .check_box('verify_certificates', label='Verify certificates') \
      .end_section() 
      
    form.set_title('OpenID Connect authentication'+('' if form_content['name'] == '' else ': '+form_content['name']))
    form.set_request_parameters({
        'scope': '@[scope]',
        'redirect_uri': '@[redirect_uri]',
        'client_secret': '@[client_secret]',
      })
    form.modify_http_parameters({
      'form_method': 'post',
      'body_format': 'x-www-form-urlencoded',
      'auth_method': 'form',
      'auth_login': '@[client_id]',
      'auth_secret': '@[client_secret]',
      'auth_login_param': 'client_id',
      'auth_secret_param': 'client_secret',
      'verify_certificates': True,
      })
    form.modify_visible_requester_fields({
      'request_url': True,
      'request_data': True,
      'form_method': True,
      'auth_method': True,
      'verify_certificates': True,
      })
    form.set_option('/clipboard/remember_secrets', True)

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())






  @register_page_url(url='form', method='GET', template='page_default.html')
  def form(self):
  
    html = """
      <form method="POST">
        <input type="text" name="prenom" value="Jean" disabled />
        <div style="display: none">
          <input type="text" name="nom" value="Valjean" disabled />
          <input type="text" name="prenom" value="Georges" />
        </div>
        <input type="submit" />
      </form>
    """
    self.add_html(html)

    
  @register_page_url(url='form', method='POST')
  def form_post(self):
    print(self.post_form)
    self.add_html('<a href="form">Retry</a>')
    
    
  @register_page_url(url='oidccallback', method='GET', template='page_default.html', continuous=True)
  def oidccallback(self):
    """ Page illustrant le démarrage d'une page à affichage progressif
    
    Cas d'usage : retour d'authentification d'un IdP, on valide le jeton, puis on peut réaliser des opérations
      qui vont s'ajouter à la page en cours : userinfo, introspection, token exchange, etc.

    La page est mise en mode continu (continuous=True), les différentes URL ajoutant du contenu devront l'être aussi
      En effet, dans le décorateur register_page_url, la gestion de l'ajout progressif du contenu n'est activée qu'en page continue
      
    On précise d'ailleurs la différence entre les deux notions (dans notre contexte propre) :
      - page continue : page dont une partie peut s'afficher sans attendre que l'ensemble des informations soit disponible.
          le cas d'usage est la récupération du jeton d'après un code : on souhaite lire le code le plus rapidement possible
          même si l'appel de l'endpoint token prend du temps
      - page à ajout progressif : page à laquelle des blocs ajoutent en fin de page au gré des demandes de l'utilisateur
          le cas d'usage, c'est l'appel à userinfo après récupération d'un jeton d'identité, on souhaite avoir sous les yeux
          l'ensemble de l'historique des actions dans la même page
          
    La terminologie pose cependant des problèmes de confusion car les deux termes sont en fait synonymes dans la vie courante
    
    L'URL oidccallback est appelée de manière normale, en web classique :
      - le décorateur register_page_url décide qu'il faut afficher la page cadre car la requête n'a pas d'en-tête CpId
          (qui est ajouté dans une variable Javascript lors de l'initialisation de la page)
      - les inclusion Javascript /javascript/requestSender.js sont réalisées
      - la variable continuousPageId est initialisée avec un nouvel identifié généré par UUID4
      - s'il est donné, le modèle de la page est affiché
      - l'affichage passe alors en mode continu
      - pour cela le décorateur lance le code Javascript getHtmlJsonContinue("GET", "/continuouspage/poll?cp_id={cp_id}");
      - le contenu est désormais uniquement transféré depuis le serveur à l'initiative du client :
      - le serveur génère du HTML et du code Javascript et le stocke dans le tampon ContinuousPageBuffer
        (au travers des méthodes add_html et add_javascript de BaseServer)
      - le client se connecte régulièrement au tampon pour en récupérer le contenu et l'afficher
      
    Une fois le bloc à afficher terminé, le serveur appelle self.send_page(), qui passe en tampon en fin de flux.
    Lors de la prochaine récupération, un indicateur de fin est envoyé au client puir qu'il arrête de consulter le tampon.
    
    L'ajout d'un nouveau bloc de contenu est déclenché par une action de l'utilisateur (clic sur un bouton de menu)
    
    la méthode Javascript fetchContent doit être appelée lors de cette action, avec l'URL générant le contenu du nouveau bloc :
      - une requête Ajax est envoyée au serveur avec l'URL de génération du contenu
      - cette URL est configurée (décorateur register_page_url) en page continue
      - et l'identifiant de page continue est transmis dans l'en-tête CpId
      - cela indique au décorateur qu'il s'agit d'un ajout d'un bloc (la page n'est donc pas initialisée avec le modèle et le code Javascript)
      - le mécanisme de consultation du tampon est remis en marche
      
    On ajoute de plus un mécanisme de masquage des éléments actionnables obsolètes, qui entrainent confusions et dysfonctionnements.
    
    On préconise que ces éléments (boutons de menu) soient regroupés dans un éléments DOM avec un identifiant uniquement
    (pour en assurer l'unicité, on prendra un UUID4).
    
    Lors de l'appel à l'URL de contenu (qui a été déclenché justement par ce menu), l'élément DOM est masqué pour que l'utilisateur
    ne puisse plus déclencher d'actions.
    
    
    
    """

    self.add_html('<h3>Callback OIDC</h3>')

    self.start_result_table()
    self.add_result_row('Code', 'did78ufj4e', 'code')
    self.end_result_table()
    self.add_html('<div class="intertable">Fetching token</div>')
    self.start_result_table()
    self.add_result_row('Operation', 'fetching token', 'code')
    self.end_result_table()
  
    menu_id = 'id'+str(uuid.uuid4())
    context_id = 'id du contexte de la page'

    self.add_html('<div id="'+html.escape(menu_id)+'">')
    self.add_html('<span><a href="retry_url?contextid='+urllib.parse.quote(context_id)+'" class="button">Retry original flow</a></span>')
    self.add_html('<span onClick="fetchContent(\'GET\',\'addcontent?contextid='+urllib.parse.quote(context_id)+'\', \'\', \''+menu_id+'\')" class="button">add content</span>')
    self.add_html('<span onClick="fetchContent(\'GET\',\'userinfo?contextid='+urllib.parse.quote(context_id)+'\', \'\', \''+menu_id+'\')" class="button">Userinfo</span>')
    self.add_html('</div>')
    
    self.send_page()
    

  @register_page_url(url='addcontent', method='GET', continuous=True)
  def addcontent(self):
    
    print("CONTENT", self.hreq.continuous_page_id)

    html_content = """
      <div>CONTENT</div>
      <div>Menu</div>
    """
    self.add_html(html_content)

    menu_id = 'id'+str(uuid.uuid4())
    context_id = 'id du contexte de la page'

    self.add_html('<div id="'+html.escape(menu_id)+'">')
    self.add_html('<span><a href="retry_url?contextid='+urllib.parse.quote(context_id)+'" class="button">Retry original flow</a></span>')
    self.add_html('<span onClick="fetchContent(\'GET\',\'addcontent?contextid='+urllib.parse.quote(context_id)+'\', \'\', \''+menu_id+'\')" class="button">add content</span>')
    self.add_html('<span onClick="fetchContent(\'GET\',\'userinfo?contextid='+urllib.parse.quote(context_id)+'\', \'\', \''+menu_id+'\')" class="button">Userinfo</span>')
    self.add_html('</div>')
    
    self.send_page()


  @register_page_url(url='userinfo', method='GET', continuous=True)
  def userinfo(self):

    form_content = {
      'name': 'Entra ID',
      'userinfo_endpoint': 'https://idp.com/userinfo',
    }
    form = RequesterForm('userinfo', form_content, action='/test/userinfo_sender', request_url='@[userinfo_endpoint]', mode='api') \
      .text('name', label='Name') \
      .text('userinfo_endpoint', label='Userinfo endpoint', clipboard_category='userinfo_endpoint')
      
    form.set_title('User Info'+('' if form_content['name'] == '' else ': '+form_content['name']))

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    self.send_page()


  @register_page_url(url='userinfo_sender', method='POST', continuous=True)
  def userinfo_sender(self):
    self.add_html('<pre>'+json.dumps(self.post_form, indent=2))
    self.send_page()


  @register_page_url(url='listonchange', method='GET', template='page_default.html', continuous=True)
  def listonchange(self):

    form_content = {
      'name': 'Entra ID',
      'access_token_list': '',
      'access_token': '',
      'introspection_endpoint': 'https://idp.com/userinfo',
    }
    form = RequesterForm('listonchange', form_content, action='/test/listonchange', request_url='@[introspection_endpoint]', mode='api') \
      .closed_list('access_token_list', label='Obtained Access Tokens', 
        values={'yesdfggs': 'OAuth 2 10:01', 'jfdosqkljf': 'OAuth 2 12:51', 'manual': 'Enter below'},
        default = 'manual',
        on_change = "let value = cfiForm.getThisFieldValue(); if (value == 'manual') { value = ''; } cfiForm.setFieldValue('access_token', value);"
        #on_change="copyATFromListToTextField({formItem}, {inputItem}, 'access_token')"
        ) \
      .text('access_token', label='Access Token', displayed_when="@[access_token_list] = 'manual'") \
      .text('introspection_endpoint', label='Introspection endpoint', clipboard_category='introspection_endpoint')
      
    form.set_title('Closed list onchange')

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    self.send_page()


  @register_page_url(url='textonload', method='GET', template='page_default.html', continuous=True)
  def textonload(self):

    form_content = {
      'redirect_uri': '',
    }
    form = RequesterForm('textonload', form_content, action='/test/textonchange', request_url='', mode='new_page') \
      .text('redirect_uri', label='Redirect URI',
        on_load = "if (cfiForm.getThisFieldValue() == '') { cfiForm.setThisFieldValue(window.location.origin + '/client/oidc/login/callback'); }")
      
    form.set_title('Text onload')

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    self.send_page()


  @register_page_url(url='datagenerator', method='GET', template='page_default.html', continuous=True)
  def datagenerator(self):

    form_content = {
      'redirect_uri': 'https://localhost/callback',
      'authorization_endpoint': 'https://idp.com',
      'oauth_flow': 'authorization_code_pkce',
      'pkce_method': 'S256',
      'pkce_code_verifier': 'pkce_code_verifier',
      'pkce_code_challenge': 'pkce_code_challenge',
      'client_id': 'ClientFedID',
      'scope': 'mail',
      'state': 'state',
    }
    
    form = RequesterForm('oauth2auth', form_content, mode='new_page', request_url='@[authorization_endpoint]') \
      .start_section('clientfedid_params', title="ClientFedID Parameters") \
        .text('redirect_uri', label='Redirect URI', clipboard_category='redirect_uri') \
      .end_section() \
      .start_section('as_endpoints', title="AS Endpoints", collapsible=True, collapsible_default=False) \
        .text('authorization_endpoint', label='Authorization Endpoint', clipboard_category='authorization_endpoint') \
      .end_section() \
      .start_section('client_params', title="Client Parameters", collapsible=True, collapsible_default=False) \
        .closed_list('oauth_flow', label='OAuth Flow', 
          values={'authorization_code': 'Authorization Code', 'authorization_code_pkce': 'Authorization Code with PKCE', 'resource_owner_password_predentials': 'Resource Owner Password Credentials', 'client_credentials': 'Client Credentials'},
          default = 'authorization_code'
          ) \
        .closed_list('pkce_method', label='PKCE Code Challenge Method', displayed_when="@[oauth_flow] = 'authorization_code_pkce'",
          values={'plain': 'plain', 'S256': 'S256'},
          default = 'S256'
          ) \
        .text('pkce_code_verifier', label='PKCE Code Verifier', displayed_when="@[oauth_flow] = 'authorization_code_pkce'") \
        .text('pkce_code_challenge', label='PKCE Code Challenge', displayed_when="@[oauth_flow] = 'authorization_code_pkce' and @[pkce_method] = 'S256'") \
        .text('client_id', label='Client ID', clipboard_category='client_id') \
        .text('scope', label='Scope', clipboard_category='scope', help_button=False) \
        .closed_list('response_type', label='Reponse type', 
          values={'code': 'code'},
          default = 'code'
          ) \
      .end_section() \
      .start_section('security_params', title="Security", collapsible=True, collapsible_default=False) \
        .text('state', label='State', clipboard_category='nonce') \
      .end_section() \

    form.set_request_parameters({
        'client_id': '@[client_id]',
        'redirect_uri': '@[redirect_uri]',
        'scope': '@[scope]',
        'response_type': '@[response_type]',
        'state': '@[state]',
        'pkce_method': '@[pkce_method]',
        'pkce_code_challenge': '@[pkce_code_challenge]',
      }, 
      modifying_fields = ['oauth_flow', 'pkce_code_verifier'])
    form.modify_http_parameters({
      'form_method': 'redirect',
      'body_format': 'x-www-form-urlencoded',
      'verify_certificates': True,
      })
    form.modify_visible_requester_fields({
      'request_url': True,
      'request_data': True,
      'body_format': False,
      'form_method': False,
      'auth_method': False,
      'verify_certificates': True,
      })
    form.set_data_generator_code("""
      if (cfiForm.getField('oauth_flow').value == 'authorization_code_pkce') {
        if (cfiForm.getField('pkce_method').value == 'plain') {
          paramValues['pkce_code_challenge'] = cfiForm.getField('pkce_code_verifier').value;
        }
      } else {
        delete paramValues['pkce_method'];
        delete paramValues['pkce_code_challenge'];
      }
      console.log(cfiForm.getField('oauth_flow').value);
      return paramValues;
    """)

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    self.send_page()


  @register_page_url(url='tables', method='GET', template='page_default.html', continuous=True)
  def tables(self):

    refresh_tokens = {
      '0': 'Direct Input',
      'token1': 'Token 1 - 03/12/2024',
      'token2': 'Token 2 - 03/12/2024',
      'token3': 'Token 3 - 03/12/2024',
      }
    default_refresh_token = '0'

    token_clients = {
      '0': '',
      'token1': 'client1',
      'token2': 'client2',
      'token3': 'client1',
      }

    form_content = {
      'refresh_token': default_refresh_token,
      'grant_type': 'refresh_token',
      'scope': '',
      }
    
    form = RequesterForm('refresh', form_content, mode='new_page', request_url='@[token_endpoint]') \
      .text('token_endpoint', label='Token endpoint', clipboard_category='token_endpoint') \
      .closed_list('refresh_token', label='Refresh Token', 
        values = refresh_tokens,
        default = default_refresh_token,
        on_change = """let value = cfiForm.getThisFieldValue(); 
          cfiForm.setFieldValue('client_id', cfiForm.getTable('token_clients')[value]);
          cfiForm.setFieldValue('client_secret', '');
          """,
        ) \
      .text('grant_type', label='Grant type', clipboard_category='grant_type') \
      .text('scope', label='Scope', clipboard_category='scope') \
      .closed_list('auth_method', label='Authn. Method', 
        values = {'none': 'None', 'basic': 'Basic', 'form': 'Form'},
        default = 'basic'
        ) \
      .text('client_id', label='Client ID', clipboard_category='client_id') \
      .password('client_secret', label='Client secret', clipboard_category='client_secret!') \

    form.set_table('token_clients', token_clients)
    form.set_request_parameters({
        'refresh_token': '@[refresh_token]',
        'grant_type': '@[grant_type]',
        'scope': '@[scope]',
      }) 
    form.modify_http_parameters({
      'request_url': '@[token_endpoint]',
      'form_method': 'post',
      'body_format': 'x-www-form-urlencoded',
      'verify_certificates': True,
      'auth_method': '@[auth_method]',
      'auth_login': '@[client_id]',
      'auth_secret': '@[client_secret]',
      })
    form.modify_visible_requester_fields({
      'request_url': True,
      'request_data': True,
      'body_format': False,
      'form_method': False,
      'auth_method': True,
      'verify_certificates': True,
      })
    form.set_option('/requester/include_empty_items', False)

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    self.send_page()
    
    
  @register_page_url(url='openlisthtml', method='GET', template='page_default.html', continuous=True)
  def openlisthtml(self):

    self.add_html('<h3>Open List Select, raw HTML version')

    self.add_javascript("""
      function openlist_change(event) {
        console.log(event);
        selectEl = event.target;
        if (selectEl.value == '#type_value') {
          selectEl.nextElementSibling.value = '';
          selectEl.nextElementSibling.focus();
        } else {
          selectEl.nextElementSibling.value = selectEl.value; 
        }
      }
      """)

    self.add_html('<div class="select-editable" style="width: 520px;">')
    self.add_html('<select onchange="openlist_change(event)" style="width: 520px;">')
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
    self.add_html('<option value="#type_value">Type value</option>')
    for option in nameid_list:
      self.add_html('<option value="'+option+'">'+option+'</option>')
    self.add_html('</select>')
    self.add_html('<input name="nameid_policy" value="'+html.escape('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified')+'" class="intable" type="text" style="width: 500px;">')
    self.add_html('</div>')
    
    
  @register_page_url(url='openlistcfiform', method='GET', template='page_default.html', continuous=True)
  def openlistform(self):

    self.add_html('<h3>Open List Select, CfiForm version</h3>')
    
    form_content = {
      'nameid_policy': 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
      'testlist': 'red',
      }
    
    form = CfiForm('samladmin', form_content, action='cfiformaction') \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name') \
        .open_list('nameid_policy', label='NameID policy', 
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
        .open_list('testlist', label='Read only list', readonly=True,
          hints = [
            'black',
            'blue',
            ]) \
      .end_section() \

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    
  @register_page_url(url='uploadbutton', method='GET', template='page_default.html', continuous=True)
  def uploadbutton(self):

    self.add_html('<h3>Upload button and textarea with upload button</h3>')
    
    form_content = {
      'name': 'Upload button',
      'certificate': '',
      }
    
    form = CfiForm('samladmin', form_content, action='cfiformaction') \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name') \
        .upload_button('upload_button', label='Upload certificate', on_upload="""
          cfiForm.setFieldValue('certificate', upload_content);
          """) \
        .textarea('certificate', label='Certificate', upload_button='Upload certificate') \
        .textarea('file', label='File', upload_button='Upload file', on_upload="alert(upload_content);") \
      .end_section() \

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
    
  @register_page_url(url='noncontinuous', method='GET', template='page_default.html', continuous=False)
  def noncontinuous(self):
    
    self.add_html("Hello")
    
    form_content = {
      'name': 'Upload button',
      'certificate': '',
      }
    
    form = CfiForm('samladmin', form_content, action='cfiformaction') \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name') \
        .upload_button('upload_button', label='Upload certificate', on_upload="""
          cfiForm.setFieldValue('certificate', upload_content);
          """) \
        .textarea('certificate', label='Certificate', upload_button='Upload certificate') \
        .textarea('file', label='File', upload_button='Upload file', on_upload="alert(upload_content);") \
      .end_section() \

    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    