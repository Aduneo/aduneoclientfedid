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

import json

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
    self.add_html('<a href="oidcauth?id=azureadaduneo">Authentification OIDC pour Azure AD</a><br>')


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
      'token_endpoint_auth_method': 'Token endpoint auth method',
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
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth method', 
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
        .closed_list('token_endpoint_auth_method', label='Token endpoint auth method', 
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
    
    
