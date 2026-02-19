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
import html
import logging
import urllib.parse
import uuid

import aduneoclientfedid.CryptoTools

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url, register_page_url
from ..Configuration import Configuration


@register_web_module('/public/auth', access={'authentication': False})
class PublicAuth(BaseHandler):
  """ Déclenche une authentification
  
  Versions:
    15/02/2026 (mpham) version initiale
  """

  @register_url(url='', method='GET')
  def auth_router(self):
    """ Aiguille vers la bonne méthode d'authentification

    Versions:
      15/02/2026 (mpham) version initiale
    """
    
    authentication_parameters = self.get_authentication_parameters()
    
    authentication_method = authentication_parameters.get('method', '')
    if authentication_method.lower() == 'generic password':
      self.send_redirection('/public/auth/password1')
    else:
      raise Exception(f"Authentication method {authentication_method} unknonwn")


