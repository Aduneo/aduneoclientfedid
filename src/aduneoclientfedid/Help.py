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
import html
import json
import logging
import os

class Help(BaseHandler):
  """ Aide en ligne accessible dans les tableaux
  
  Pour modifier le texte de l'aide directement dans l'app, on passe le paramètre de configuration /preferences/help/edit_topics à on
    Cela ajoute un bouton de modification dans la fenêtre de popup
    
    On peut modifier :
      - le titre
      - le contenu
      
    Le contenu suit une syntaxe de type markdown très simplifié :
      - l'italique est l'astérisque seule : *italique*
      - le gras est une double astérique : **gras**
      - le gras+italique est une triple astérique : ***gras+italique***
      - le retour à la ligne se fait en terminant une ligne par deux espaces ou par <br>
      - une liste se fait en commençant chaque ligne par un tiret -
      - une liste numérotée se fait en commençant chaque ligne par un nombre suivi d'un point (le nombre n'a pas d'importance)
  
  """
  
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
    
    #Help.help_json = None
    if Help.help_json is None:
    
      data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
      help_filepath = os.path.join(data_dir, 'help.json')

      with open(help_filepath, encoding='utf8') as json_file:
        Help.help_json = json.load(json_file)

    language = 'en'
    response = {
      'help_id': help_id,
      'language': language,
      'edit_topics': self.conf.is_on('preferences/help/edit_topics')
      }
    
    help_item = Help.help_json.get(help_id)
    if help_item:
    
      content = help_item.get('content_'+language)
      content_format = help_item.get('format_'+language, 'html')
      if content_format == 'text':
        content = html.escape(content)
      elif content_format == 'lmd':
        content = Help.convert_from_light_markdown(content)
    
      response.update({
        'header': html.escape(help_item.get('header_'+language)),
        'content': content,
        'topics_defined': True,
        })
      if self.conf.is_on('preferences/help/edit_topics'):
        response['edit_content'] = html.escape(help_item.get('content_'+language))
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


  def save_help(self):
    """ Enregistre de nouveaux textes pour une rubrique d'aide

    Returns:
      une page avec un code 200 si tout c'est bien déroulé
      une page avec un code 500 en cas d'erreur
    
    Versions:
      24/02/2024 (mpham) version initiale
    """
    
    code = 200
    
    if self.conf.is_on('preferences/help/edit_topics'):

      try:

        # on charge le fichier dans le cas où le cache n'est pas à jour
        data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
        help_filepath = os.path.join(data_dir, 'help.json')

        with open(help_filepath, encoding='utf8') as json_file:
          Help.help_json = json.load(json_file)

        help_id = self.post_form['help_id']
        language = self.post_form['language']
        
        help_item = Help.help_json.get(help_id)
        if help_item is None:
          Help.help_json[help_id] = {}
          help_item = Help.help_json.get(help_id)
        help_item['header_'+language] = self.post_form['header']
        help_item['content_'+language] = self.post_form['content']
        help_item['format_'+language] = 'lmd'
        
        with open(help_filepath, 'w', encoding='utf8') as json_file:
          json.dump(Help.help_json, json_file, indent=2, ensure_ascii=False)
          
      except Exception as e:
        logging.error(f"can't save help topic : {e}")
        code = 500

    self.send_page(code=code)


  def convert_from_light_markdown(text:str) -> str:
    """ Convertit du light markdown en HTML
    
    Voir le commentaire de la classe pour une description du light markdown de ClientFedID
    
    Args:
      text : texte en light markdown
      
    Returns:
      Code HTML correspondant
      
    Raises:
      AduneoError en cas de conversion impossible
    
    Versions:
      24/02/2024 (mpham) version initiale
    """
    
    result = ''
    
    current_syntax = 'none'
    for line in text.split('\n'):
      
      line_syntax = 'paragraph'
      if line == '':
        line_syntax = 'new paragraph'
      elif line.startswith('- '):
        line_syntax = 'unordered list'
        line = line[2:].strip()
      elif line[0].isnumeric():
        dot_pos = line.find('.')
        if dot_pos>0:
          if line[:dot_pos].isnumeric():
            line_syntax = 'ordered list'
            line = line[dot_pos+1:].strip()
      
      if line_syntax != current_syntax:
        
        if current_syntax == 'paragraph':
          result += '</p>'
        elif current_syntax == 'unordered list':
          result += '</ul>'
        elif current_syntax == 'ordered list':
          result += '</ol>'
          
        if line_syntax == 'paragraph':
          result += '<p>'
        elif line_syntax == 'unordered list':
          result += '<ul>'
        elif line_syntax == 'ordered list':
          result += '<ol>'
          
      if line_syntax == 'paragraph':
        line_break = False
        if line.endswith('  '):
          line_break = True
          line = line.strip()
        elif line.endswith('<br>'):
          line_break = True
          line = line[:-4]
      
        result += Help._convert_text_from_light_markdown(line.strip())
        if line_break:
          result += '<br/>'
      elif line_syntax == 'unordered list' or line_syntax == 'ordered list':
        result += '<li>'+ Help._convert_text_from_light_markdown(line.strip()) + '</li>'

      current_syntax = line_syntax

    if current_syntax == 'paragraph':
      result += '</p>'
    elif current_syntax == 'unordered list':
      result += '</ul>'
    elif current_syntax == 'ordered list':
      result += '</ol>'

    return result
    
    
  def _convert_text_from_light_markdown(text:str) -> str:
    """ Convertit un paragraphe light markdown en HTML
    
    (la différence avec convert_from_light_markdown, c'est qu'on ne traite que la décoration du texte : italique et gras)
    
    Voir le commentaire de la classe pour une description du light markdown de ClientFedID
    
    Args:
      text : paragraphe en light markdown
      
    Returns:
      Code HTML correspondant
      
    Raises:
      AduneoError en cas de conversion impossible
    
    Versions:
      24/02/2024 (mpham) version initiale
    """
    
    start = 0
    
    text = text.replace('\\*', chr(1))
    
    result = ''
    loop = True
    while loop:
      
      start_asterisk_pos = text.find('*', start)
      if start_asterisk_pos == -1:
        result += html.escape(text[start:])
        loop = False
      else:
        asterisk_count = Help._count_asterisks(text, start_asterisk_pos)
        if asterisk_count>3:
          raise AduneoError(f"too many asterisks at postition {start_asterisk_pos} in light markdown string {text}")
        if start_asterisk_pos+asterisk_count >= len(text):
          raise AduneoError(f"no ending asterisks at postition {start_asterisk_pos} in light markdown string {text}")
        end_asterisk_pos = text.find('*', start_asterisk_pos+asterisk_count+1)
        if end_asterisk_pos == -1:
          raise AduneoError(f"no ending asterisks at postition {start_asterisk_pos} in light markdown string {text}")
        end_asterisk_count = Help._count_asterisks(text, end_asterisk_pos)
        if end_asterisk_count != asterisk_count:
          raise AduneoError(f"ending asterisks don't match starting asterisks at postition {end_asterisk_pos} in light markdown string {text}")
        
        start_tag = {1: '<em>', 2: '<strong>', 3: '<em><strong>'}[asterisk_count]
        end_tag = {1: '</em>', 2: '</strong>', 3: '</strong></em>'}[asterisk_count]
        
        result += html.escape(text[start:start_asterisk_pos]) + start_tag + html.escape(text[start_asterisk_pos+asterisk_count:end_asterisk_pos]) + end_tag
        start = end_asterisk_pos+asterisk_count

    return result.replace(chr(1), '*')
    
    
  def _count_asterisks(text:str, asterisk_pos:int) -> int:
    """ Compte le nombre d'astériques contiguës
    
    Args:
      text: texte concerné
      asterisk_pos: position de la première astérisque
      
    Returns:
      nombre d'astérisques
      
    Versions:
      24/02/2024 (mpham) version initiale
    """
    
    count = 0
    loop = True
    while loop:
      if asterisk_pos>=len(text):
        loop = False
      else:
        if text[asterisk_pos] != '*':
          loop = False
        else:
          count += 1
          asterisk_pos += 1
          
    return count
      
    