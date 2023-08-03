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
from ..BaseServer import register_web_module, register_api_url
from threading import Lock


"""
Exemple d'utilisation :

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=True)
  def prepare_request(self):

    print('HELLO')
    self.add_javascript_include('/javascript/resultTable.js')
    self.add_html('ENCORE HELLO<b>Oh oh</b>')
    self.add_javascript('console.log("LEROY");')
    
    self.add_html('Blah blah')
    self.send_page('Rohhh')

"""

class ContinuousPageBuffer(object):
  
  buffer = {}
  buffer_lock = Lock()
  
  def add_content(cp_id:str, html:str=None, javascript:str=None, javascript_include:str=None, stop:bool=False):
    """ Ajoute au tampon du contenu
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      html: code HTML, qui ne doit pas contenir de Javascript (car il ne sera pas exécuté)
      javascript: code Javascript, sans les balises <script>, qui sera exécuté après le HTML
      javascript_include: URL d'include Javascript, qui sera intégrée avant l'exécution du code Javascript
      stop: indique si le polling doit s'arrêter (fin de la page ou fin de section de page)
    
    Versions:
      29/03/2023 (mpham) version initiale
    """
    
    with ContinuousPageBuffer.buffer_lock:
    
      if cp_id not in ContinuousPageBuffer.buffer:
        ContinuousPageBuffer.buffer[cp_id] = {'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}
        
      if html:
        ContinuousPageBuffer.buffer[cp_id]['html'] += html

      if javascript:
        ContinuousPageBuffer.buffer[cp_id]['javascript'] += javascript
        
      if javascript_include:
        ContinuousPageBuffer.buffer[cp_id]['javascript_include'].append(javascript_include)
        
      if stop:
        ContinuousPageBuffer.buffer[cp_id]['stop'] = True

  
  def get_buffer(cp_id:str) -> dict:
    """ Retourne le buffer d'un navigateur
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      
    Returns:
      Un dict avec les éléments suivants :
        - html : code HTML
        - javascript : code Javascript, avec les balises <script>
        - javascript_include : tableau d'URL de fichiers Javascript à inclure
    
    Versions:
      29/03/2023 (mpham) version initiale
    """

    buffer = {'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}

    with ContinuousPageBuffer.buffer_lock:
      if cp_id in ContinuousPageBuffer.buffer:
        #print('---- cp_id trouvé ----')
        buffer = ContinuousPageBuffer.buffer[cp_id]
        ContinuousPageBuffer.buffer.pop(cp_id)
        
    return buffer
  

@register_web_module('/continuouspage')
class ContinuousPage(BaseHandler):

  @register_api_url(method='GET')
  def poll(self):
  
    cp_id = self.get_query_string_param('cp_id')
    
    buffer = ContinuousPageBuffer.get_buffer(cp_id)
    #print(buffer)
    
    self.send_json(buffer)

