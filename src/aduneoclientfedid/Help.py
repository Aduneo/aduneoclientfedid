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

from .BaseServer import AduneoError
from .BaseServer import BaseHandler
from .Configuration import Configuration
import json
import logging
import os

class Help(BaseHandler):
  
  help_json = None
  
  
  def help_window_definition(page_id:str=None):
    
    """Retourne le code HTML et Javascript de la fenêtre d'affichage de l'aide
    
    :return: code HTML
    :rtype: str
    
    .. notes::
      mpham 23/04/2021
    """
    
    page_id_code = ''
    if page_id:
      page_id_code = '<script>helpRootPageId = "'+page_id+'";</script>'
    
    return """
      <link rel="stylesheet" href="/css/dragWindow.css">
      <script src="/javascript/help.js"></script>
      """+page_id_code+"""
    
      <div id="helpWindow" class="dragWindow" onmousedown="startDrag(this, event)">
        <div class="dragHeader"><span id="helpHeader"></span><span style="float: right; cursor: pointer;" onclick="closeDrag(this)">&#x2716;</span></div>
        <div id="helpContent" class="dragContent">
        </div>
      </div>
      """
      
      
  def add_window_definitition_to_continous_page(page:BaseHandler):
  
    """
      Ajoute les éléments HTML de la page d'aide à une page de type continue

      Rappel, pour créer une page continue, on ajoute un décorateur
      
        @register_page_url(url='<url>', continuous=True)

    Arguments:
      page: héritier de BaseHandler, de type continous
    
    Versions:
      03/08/2023 (mpham) : version initiale en copiant le HTML de help_window_definition
    """
    
    page.add_javascript_include("/javascript/help.js")
    page.add_html("""
      <link rel="stylesheet" href="/css/dragWindow.css">
      <script src="/javascript/help.js"></script>
    
      <div id="helpWindow" class="dragWindow" onmousedown="startDrag(this, event)">
        <div class="dragHeader"><span id="helpHeader"></span><span style="float: right; cursor: pointer;" onclick="closeDrag(this)">&#x2716;</span></div>
        <div id="helpContent" class="dragContent">
        </div>
      </div>
      """)
  
  
  def send_help(self):
    
    """
    Retourne les rubriques d'aide sous forme de JSON
      "header": "..."
      "content" : "...'
      
    mpham 13/04/2021
    """
  
    help_id = self.get_query_string_param('id', '')
    
    Help.help_json = None
    if Help.help_json is None:
    
      data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
      print(data_dir)
      help_filepath = os.path.join(data_dir, 'help.json')

      with open(help_filepath, encoding='utf8') as json_file:
        Help.help_json = json.load(json_file)

    language = 'en'
    response = {}
    
    help_item = Help.help_json.get(help_id)
    if help_item:
      response['header'] = help_item.get('header_'+language)
      response['content'] = help_item.get('content_'+language)
    else:
      response['header'] = help_id
      response['content'] = 'help entry '+help_id+" not found for language "+language
      logging.error('help entry '+help_id+' not found in help.json')
    
    self.send_json(response)
