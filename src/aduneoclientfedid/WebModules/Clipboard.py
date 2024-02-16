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
from ..CryptoTools import CryptoTools
import json
import os
import uuid


class ClipboardContent(object):
  
  file_path = Configuration.conf_dir+'/clipboardContent.json'
  
  def __init__(self, conf:dict):
    
    self.conf = conf
    self.content = {}
    if os.path.isfile(ClipboardContent.file_path):
      with open(ClipboardContent.file_path, encoding='utf8') as json_file:
        if Configuration.is_parameter_on(self.conf, '/preferences/clipboard/encrypt_clipboard', True):
          key_file_path = self._get_key_file_path()
          crypto = CryptoTools(key_file_path)
          file_content = json_file.read()
          self.content = json.loads(crypto.decrypt_string(file_content))
        else:
          self.content = json.load(json_file)

      
  def save(self):
    
    if Configuration.is_parameter_on(self.conf, '/preferences/clipboard/encrypt_clipboard', True):
      key_file_path = self._get_key_file_path()
      crypto = CryptoTools(key_file_path)
      file_content = crypto.encrypt_string(json.dumps(self.content))
    else:
      file_content = json.dumps(self.content)
    
    with open(ClipboardContent.file_path, 'w', encoding='utf8') as json_file:
      json_file.write(file_content)

  
  def add_text(self, category:str, text:str):
    
    add = True
    
    
    # OBSOLETE : les champs secrets ne ne terminent plus par !
    if category.endswith('!'):
      # on regarde si on doit bien stocker les secrets
      add = Configuration.is_parameter_on(self.conf, '/preferences/clipboard/remember_secrets', False)
    
    if add:
      if category not in self.content:
        self.content[category] = []
      exists = False
      for saved_text in self.content[category]:
        if saved_text['text'] == text:
          exists = True
        
      if not exists:
        self.content[category].insert(0, {'id': str(uuid.uuid4()), 'text': text})
      
      
  def get_texts(self, category:str):
    
    texts = []
    
    if category == 'all':
      for cat in self.content:
        for saved_text in self.content[cat]:
          texts.append(saved_text)
    elif category in self.content:
      texts = self.content[category]
      
    return texts


  def remove_text(self, text_id:str):
    
    new_content = {}
    
    for category in self.content:
      new_content[category] = []
      for saved_text in self.content[category]:
        if saved_text['id'] != text_id:
          new_content[category].append(saved_text)
        
    self.content = new_content
    self.save()
      
  
  def _get_key_file_path(self) -> str:
    """ Retourne le chemin complet de la clé de chiffrement référencée dans la configuration dans /meta/key
    
    Returns:
      chemin complet du fichier contenant la clé
      
    Raises:
      AduneoError si la clé n'est pas trouvée
      
    Versions:
      28/12/2022 (mpham) : version initiale copiée de l'ancien Configuration.get_cipher()
    """

    key_filename = None
    if 'meta' in self.conf:
      if 'key' in self.conf['meta']:
        key_filename = self.conf['meta']['key']
        
    if key_filename is None: 
      raise AduneoError('encryption: key file name not found in configuration (should be in /meta/key')
  
    return os.path.join(Configuration.conf_dir, key_filename)
  

@register_web_module('/client/clipboard')
class Clipboard(BaseHandler):

  content = None
  
  def get_window_definition():
    return """
<script src="/javascript/clipboard.js"></script>
<script src="/javascript/dragWindow.js"></script>
<div id="clipboardWindowBackground" class="modal-background" onclick="clipboardClickBackground(event)">
</div>
<div id="clipboardWindow" class="dragWindow" style="z-index: 2;" onmousedown="startDrag(this, event)">
  <div class="dragHeader"><span id="clipboardHeader">ClientFedID clipboard<span style="margin-left:60px;"><span><span onclick="refreshClipboard('all')" class="middleButton">All</span><span style="margin-left:12px;"><span><span id="clipboardSpecific" onclick="refreshClipboard()" class="middleButton"></span></span><span style="float: right; cursor: pointer;" onclick="closeClipboard()">&#x2716;</span></div>
  <div id="clipboardContent" class="dragContent">
    <div id="clipboardChoiceTemplate" class="choiceButton" onclick="selectClipboardText(this)" style="display: none;"><span class="choiceText"></span><span style="float: right; cursor: pointer;"><img onclick="removeClipboardText(event, this)" src="/images/clear.png" width="12px"></span></div>
  </div>
</div>
"""    
  
  @register_url(method='POST')
  def update(self):
    for category in self.post_json:
      for text in self.post_json[category]:
        self._get_content().add_text(category, text)
    
    self._get_content().save()
    
    self.send_page_raw()

    
  @register_url(method='GET')
  def get(self):
    
    category = self.get_query_string_param('category')
    
    self.send_json(self._get_content().get_texts(category))
    
    
  @register_url(method='GET')
  def remove(self):
    """
    Il serait préférable que la méthode soit DELETE
    """
    
    text_id = self.get_query_string_param('id')
    self._get_content().remove_text(text_id)
    
    self.send_page_raw()
    
  
  def _get_content(self) -> ClipboardContent:
    
    if not Clipboard.content:
      Clipboard.content = ClipboardContent(self.conf)

    return Clipboard.content


