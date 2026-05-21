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
import urllib.parse
import html
import json
import logging
import os
import markdown

from .BaseServer import register_web_module, register_url, register_page_url

@register_web_module('/help')
class Help(BaseHandler):
  """ Aide en ligne accessible dans les tableaux
  
  Pour modifier le texte de l'aide directement dans l'app, on passe le paramètre de configuration /preferences/help/edit_topics à on
    Cela ajoute un bouton de modification dans la fenêtre de popup
    
    On peut modifier :
      - le titre
      - le contenu
      
    Le contenu suit une syntaxe markdown, par exemple :
      - l'italique est l'astérisque seule : *italique*
      - le gras est une double astérique : **gras**
      - le gras+italique est une triple astérique : ***gras+italique***
      - le retour à la ligne se fait en terminant une ligne par deux espaces ou par <br>
      - une liste se fait en commençant chaque ligne par un tiret -
      - une liste numérotée se fait en commençant chaque ligne par un nombre suivi d'un point (le nombre n'a pas d'importance)
  
  """
  
  help_json = None
  edit_topics = True
  
  
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
  
  @register_url(url='sendHelp', method='GET')
  def send_help(self):
    """ Retourne les rubriques d'aide sous forme de JSON
      "header": "...",
      "content": "...",
      "edit_topics": True/False,
      "topic_defined": True/False,
      "help_id":  "...",
      "language":  "..."
    
    Versions    
      13/04/2021 (mpham) version initiale
      21/20/2024 (mpham) l'utilisateur peut avoir la posibilité de modifier le texte d'aide (si paramètre de configuration preferences/help/edit_topics à on
      24/02/2024 (mpham) on envoie maintenant les informations nécessaires à la modification du texte : help_id, language, edit_topics (true/false) et edit_content (contenu au format light markdown)
    """
  
    help_id = self.get_query_string_param('id', '')
    
    if Help.help_json is None:
    
      data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
      help_filepath = os.path.join(data_dir, 'help.json')

      with open(help_filepath, encoding='utf8') as json_file:
        Help.help_json = json.load(json_file)

    language = 'fr'
    response = {
      'help_id': help_id,
      'language': language,
      'edit_topics': Help.edit_topics
      }
    
    help_item = Help.help_json.get(help_id)
    if help_item:
    
      content = help_item.get('content_'+language)
      content_format = help_item.get('format_'+language)
      if content_format == 'md':
        content = markdown.markdown(content)
      else :
        raise AduneoError("Unsupported help window content passed")
    
      response.update({
        'header': help_item.get('header_'+language),
        'content': content,
        'topics_defined': True,
        })
      if Help.edit_topics:
        response['edit_content'] = help_item.get('content_'+language)
      else:
        response['edit_content'] = ''

    else:
      response.update({
        'header': help_id,
        'content': 'help entry '+help_id+" not found for language "+language,
        'topics_defined': False,
        })
      logging.error('help entry '+help_id+' not found in help.json')
    
    self.send_json(response)

  @register_url(url='saveHelp', method='POST')
  def save_help(self):
    """ Enregistre de nouveaux textes pour une rubrique d'aide

    Retourne la rubriques d'aide enregistrée sous forme de JSON
    
    Versions:
      24/02/2024 (mpham) version initiale
      22/04/2026 (vbittard) modification pour display après sauvegarde
    """
    
    if Help.edit_topics:

      try:

        # on charge le fichier dans le cas où le cache n'est pas à jour
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        help_filepath = os.path.join(data_dir, 'help.json')

        with open(help_filepath, encoding='utf8') as json_file:
          Help.help_json = json.load(json_file)

        help_id = urllib.parse.unquote_plus(self.post_form['help_id'])
        language = urllib.parse.unquote_plus(self.post_form['language'])
        header   = urllib.parse.unquote_plus(self.post_form['header'])
        content  = urllib.parse.unquote_plus(self.post_form['content'])
        
        help_item = Help.help_json.get(help_id)
        if help_item is None:
          Help.help_json[help_id] = {}
          help_item = Help.help_json.get(help_id)
        help_item['header_'+language] = header
        help_item['content_'+language] = content
        help_item['format_'+language] = 'md'
        
        with open(help_filepath, 'w', encoding='utf8') as json_file:
          json.dump(Help.help_json, json_file, indent=2, ensure_ascii=False)
          
      except Exception as e:
        logging.error(f"can't save help topic : {e}")

    response={
      'help_id': self.post_form['help_id'],
      'language': self.post_form['language'],
      'edit_topics': Help.edit_topics,
      'header': self.post_form['header'],
      'content': markdown.markdown(self.post_form['content']),
      'topics_defined': True,
      'edit_content' : self.post_form['content']
    }

    self.send_json(response)