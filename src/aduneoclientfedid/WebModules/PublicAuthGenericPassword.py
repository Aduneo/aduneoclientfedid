"""
Copyright 2026 Aduneo

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
import logging
import uuid

import aduneoclientfedid.CryptoTools

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url, register_page_url
from ..Configuration import Configuration
from ..authprotection.AuthProtection import AuthProtection


@register_web_module('/public/auth/password1', access={'authentication': False})
class PublicAuthGenericPassword(BaseHandler):
  """ Authentification par mot de passe avec un unique utilisateur
  (protection de base de niveau de sécurité faible)
  
  Versions:
    13/02/2026 (mpham) version initiale
  """

  @register_page_url(url='', method='GET', template='auth_password.html')
  def auth_page(self):
    """ Mire d'authentification

    Versions:
      13/02/2026 (mpham) version initiale
    """
    
    csrf_token = str(uuid.uuid4())
    self.set_session_value('token', csrf_token)
    self.add_html(f"""
    
<form action="password1/login" method="post">
  <input type="hidden" name="token" value="{csrf_token}">
  <div>Login <input type="text" name="login" value=""></div>
  <div>Password <input type="password" name="password" value=""></div>
  <div><input type="submit" name="Log in"></div>
</form>
    
    """)
    

  @register_url(url='login', method='POST')
  def login(self):
    """ Vérification d'authentification

    Versions:
      13/02/2026 - 20/02/2026 (mpham) version initiale
    """
    
    auth_protection = AuthProtection()
    
    if self.post_form.get('token', 'error') != self.get_session_value('token'):
      self.send_redirection('/public/auth/password1')
      return
    
    authentication_parameters = self.get_authentication_parameters()
    
    conf_login = authentication_parameters.get('login')
    if not conf_login:
      raise AduneoError("no login configured")
    user_login = self.post_form['login'].lower()
    if conf_login.lower() != user_login:
      logging.info(f"Authentication failed: unknown login {user_login}")
      self.send_redirection('/public/auth/password1')
      return

    if not auth_protection.is_auth_allowed(conf_login, self):
      logging.info(f"Authentication failed: authentication protection activated for {self.post_form['login']} from {self.ip_address}")
      self.send_redirection('/public/auth/password1')
      return

    conf_password_hash = authentication_parameters.get('password%')
    if not conf_password_hash:
      raise AduneoError("no password configured")
      
    password_tools = aduneoclientfedid.CryptoTools.PasswordTools()
    if not password_tools.verify_password(hash_value=conf_password_hash, password=self.post_form['password']):
      logging.info(f"Authentication failed: bad password for login {user_login}")
      auth_protection.failed_auth(conf_login, self)
      self.send_redirection('/public/auth/password1')
      return

    self.set_session_value('authentication', {'user': conf_login})
    auth_protection.successful_auth(conf_login, self)

    self.send_redirection('/')


