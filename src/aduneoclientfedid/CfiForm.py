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
import requests
import uuid

from .BaseServer import AduneoError
from .BaseServer import DesignError
from .Proposition import Proposition


class CfiForm():
  """ Formulaires générés à partir de templates
  
  Utilisables en en pages normales et en pages continues
  
  On sépare le modèle et les données
  
  Le modèle est construit en appelant des méthodes :
    text pour les INPUT type="TEXT"
    textarea pour les TEXTAREA
    closed_list pour les SELECT
    start_section pour commencer un tableau
    end_section pour terminer un tableau
    
  Exemple de définition de modèle :
    form = CfiForm('oidcadmin', form_content) \
      .start_section('section_general', title="General configuration") \
        .text('name', label='Name') \
        .text('redirect_uri', label='Redirect URI', help_button=False) \
        .closed_list('endpoint_configuration', label='Endpoint configuration', 
          values={'discovery_uri': 'Discovery URI', 'local_configuration': 'Local configuration'},
          default = 'discovery_uri'
          ) \
      .end_section() \

  Le contenu est un dict à plat passé dans le constructeur
  
  Exemple de contenu
    form_content = {
      'name': 'Configuration OpenID Connect',
      'redirect_uri': 'https://localhost/client/callback',
      'endpoint_configuration': 'discovery_uri',
      'signature_key_configuration': 'local_configuration',
      'verify_certificates': True,
      }

  On récupère de manière séparée
    le HTML par get_html()
    le code Javascript associé par get_javascript
    
  L'inclusion dans une page se fait donc naturellement par
    self.add_html(form.get_html())
    self.add_javascript(form.get_javascript())
    
  On peut fournir au formulaire des données accessible au Javascript au travers des tables.
    form.set_table('token_clients', {'0': 'client1', '19': 'client2'})
  
    on_change = ""let value = cfiForm.getThisFieldValue(); 
      cfiForm.setFieldValue('client_id', cfiForm.getTable('token_clients')[value]);
      cfiForm.setFieldValue('client_secret', '');
      "",
    ) \
    (mettre 3 guillemets au lieu de 2)
  
  Versions:
    27/12/2023 (mpham) version initiale
    03/12/2024 (mpham) ajout des tables : dictionnaires clé / valeur utilisables par le Javascript (on_change en particulier)
  """

  def __init__(self, form_id:str, content:dict, action:str=None, mode:str='new_page', submit_label:str=None):
    """ Constructeur
    
    Args:
      form_id: identifiant du formulaire, essentiellement utiliser pour les codes d'affichage de l'aide en ligne
      content: dict à plat contenant les valeurs par défaut des champs
      action: URL où envoyer le formulaire
      mode: indique comment le formulaire est envoyé
        - new_page : mode normal où la réponse remplace la page
        - api : la requête est effectuée par ClientFedID en service web et la réponse est ajoutée dans la page courante, juste après le formulaire
      submit_label: libellé du bouton de soumission du formulaire
    
    Versions:
      27/12/2023 (mpham) version initiale
      30/08/2024 (mpham) options /requester/auth_method_options
      27/11/2024 (mpham) option /requester/include_empty_items qui indique si le contenu du formulaire doit contenir les éléments sans valeur
      03/12/2024 (mpham) tables contenant des valeurs exploitables par le Javascript
    """
  
    self.form_id = form_id
    self.action = action
    self.mode = mode
    self.submit_label = submit_label
    self.form_uuid = 'i'+str(uuid.uuid4()).replace('-', '_') # car on utilise dom_id dans le nom de fonctions Javascript, et document.querySelectorAll n'aime pas les classes commençant par un chiffre

    # Template (construit par les méthodes text(), closed_list(), check_box(), etc.)
    self.template = []
    
    # Contenu
    self.title = None
    self.content = content
    self.tables = {}
    
    # Pour génération HTML et Javascript
    self.html = None
    self.javascript = None 
    self.selects_with_triggers = []
    self.items_with_conditions = []
    self.in_table = False
    
    # Options : /clipboard/remember_secrets uniquement
    self.options = {
      '/clipboard/remember_secrets': False,
      '/requester/cancel_button': None,
      '/requester/auth_method_options': None,
      '/requester/include_empty_items': True,
    }
    
  
  def set_title(self, title:str):
    self.title = title


  def text(self, field_id:str, label:str='', clipboard_category:str=None, copy_value:bool=True, help_button:bool=True, displayed_when:str="True", readonly:bool=False, on_load=None):
  
    text = self._add_template_item('text', field_id, label, help_button, displayed_when, readonly)
    text['clipboard_category'] = clipboard_category
    text['copy_value'] = copy_value
    text['on_load'] = on_load
    return self


  def password(self, field_id:str, label:str='', clipboard_category:str=None, copy_value:bool=True, help_button:bool=True, displayed_when:str="True", readonly:bool=False):
  
    text = self._add_template_item('password', field_id, label, help_button, displayed_when, readonly)
    text['clipboard_category'] = clipboard_category
    text['copy_value'] = copy_value
    return self


  def textarea(self, field_id:str, label:str='', rows=4, clipboard_category:str=None, copy_value:bool=True, help_button:bool=True, displayed_when:str="True", readonly:bool=False):
  
    textarea = self._add_template_item('textarea', field_id, label, help_button, displayed_when, readonly)
    textarea['rows'] = rows
    textarea['clipboard_category'] = clipboard_category
    textarea['copy_value'] = copy_value
    return self


  def closed_list(self, field_id:str, label:str='', values:dict={}, default:str='', help_button:bool=True, displayed_when:str="True", readonly:bool=False, on_load=None, on_change=None):
    """
      Versions:
        11/08/2024 (mpham) événements on_load et on_change
    """

    closed_list = self._add_template_item('closed_list', field_id, label, help_button, displayed_when, readonly)
    closed_list['values'] = values
    closed_list['default'] = default
    if on_load:
      closed_list['on_load'] = on_load
    if on_change:
      closed_list['on_change'] = on_change
    return self


  def hidden(self, field_id:str):
  
    self._add_template_item('hidden', field_id)
    return self
  
  
  def check_box(self, field_id:str, label:str='', help_button:bool=True, displayed_when:str="True", readonly:bool=False):
  
    self._add_template_item('check_box', field_id, label, help_button, displayed_when, readonly)
    return self
  
  
  def start_section(self, section_id:str, title:str, help_button:bool=True, level:int=1, collapsible:bool=False, collapsible_default:bool=False, displayed_when:str="True"):

    section = self._add_template_item('start_section', section_id, title, help_button, displayed_when, holds_value=False)
    section['level'] = level
    section['collapsible'] = collapsible
    section['collapsible_default'] = collapsible_default
    return self


  def end_section(self):
    self._add_template_item('end_section', None, '', False, {}, holds_value=False)
    return self


  def raw_html(self, html:str):
    raw_html = self._add_template_item('raw_html', None, '', False, {}, holds_value=False)
    raw_html['html'] = html
    return self


  def set_table(self, table_id:str, table:dict):
    """ Ajoute une table au formulaire
    
    Args:
      table_id: un identifiant permettant au Javascript de récupérer la table
      table: la table en tant que telle, dont les valeurs sont libres, mais doivent être représentables par du JSON
      
    Versions:
      03/12/2024 (mpham) version initiale
    """
    
    self.tables[table_id] = table
    

  def get_html(self):

    if self.html is None:
      self._generate_code()
    
    return self.html
    
  
  def get_javascript(self):

    if self.javascript is None:
      self._generate_code()
  
    return self.javascript


  def set_option(self, option_name:str, option_value):
    
    if option_name not in self.options.keys():
      raise DesignError('option {option} not supported'.format(option=option_name))
    self.options[option_name] = option_value
    

  def _add_template_item(self, item_type:str, item_id:str, label:str='', help_button:bool=True, displayed_when:str="True", readonly:bool=False, holds_value=True):

    item = {
      'type': item_type,
      'id': item_id,
      'label': label,
      'help_button': help_button,
      'displayed_when': displayed_when,
      'readonly': readonly,
      'holds_value': holds_value,
      }
      
    self.template.append(item)
    
    return item
  
  
  def _generate_code(self):

    code_generator = CodeGenerator(self)
    code_generator.generate()
    self.html = code_generator.html
    self.javascript = code_generator.javascript


class CodeGenerator():
  
  def __init__(self, form):
    self.form = form

  
  def generate(self):
    """
      Versions:
        11/08/2024 (mpham) événement onchange
        12/03/2024 (mpham) tables contenant des valeurs accessibles au Javascript
    """

    self.html = '<form id="form-'+self.form.form_uuid+'" method="POST" {action}">'.format(
      action = 'action="'+self.form.action+'"' if self.form.action else ''
      )
    self.javascript = ''
    self.selects_with_triggers = []
    self.items_with_conditions = []
    self.in_table = False

    if self.form.title:
      self.html += '<h1>{title}</h1>'.format(title=self.form.title)
  
    for template_item in self.form.template:
      
      if template_item['type'] == 'text':
        self._generate_code_text(template_item)
      elif template_item['type'] == 'password':
        self._generate_code_password(template_item)
      elif template_item['type'] == 'textarea':
        self._generate_code_textarea(template_item)
      elif template_item['type'] == 'closed_list':
        self._generate_code_closed_list(template_item)
      elif template_item['type'] == 'check_box':
        self._generate_code_check_box(template_item)
      elif template_item['type'] == 'hidden':
        self._generate_code_hidden(template_item)
      elif template_item['type'] == 'start_section':
        self._generate_code_start_section(template_item)
      elif template_item['type'] == 'end_section':
        self._generate_code_end_section(template_item)
      elif template_item['type'] == 'raw_html':
        self._generate_code_raw_html(template_item)
      else:
        raise DesignError('code generation for CfiForm, unknown item type {type}'.format(type=template_item['type']))

    self._end_table()
    
    self.html += '<div id="'+html.escape(self.form.form_uuid)+'_button_bar">'
    self.html += '<span class="middlebutton" onClick="reinitFormRequest(\''+html.escape(self.form.form_uuid)+'\')">Reinit request</span>'

    if self.form.mode == 'new_page':
      label = self.form.submit_label
      if label is None:
        label = 'Send'
      #self.html += f'<span class="middlebutton" onClick="document.getElementById(\'form-{html.escape(self.form.form_uuid)}\').submit();">{label}</span>'
      self.html += f'<span class="middlebutton" onClick="sendToRequester_newPage(\'{html.escape(self.form.form_uuid)}\')">{label}</span>'
    else:
      label = self.form.submit_label
      if label is None:
        label = 'Send request'
      self.html += f'<span class="middlebutton" onClick="sendToRequester_api(\'{html.escape(self.form.form_uuid)}\')">{label}</span>'
      if self.form.options['/requester/cancel_button']:
        self.html += f'<span class="middlebutton" onClick="cancelRequester_api(\'{html.escape(self.form.form_uuid)}\', \'{self.form.options["/requester/cancel_button"]}\')">Cancel</span>'
    
    #self.html += '<span class="middlebutton" onClick="cancelRequest(\''+html.escape(self.form.form_uuid)+'\', \''+html.escape(context)+'\')">Cancel</span>'
    self.html += '</div>'
    self.html += '<div id="'+html.escape(self.form.form_uuid)+'_send_notification" style="display: none;">'
    self.html += '<h3>Sending request...</h3>'
    self.html += '</div>'
    
    
    self.html += '</form>'

    # Pour le Javascript, on commence par ajouter les tables pour que les données soient tout de suite disponibles
    self.javascript += f"""var tables_{self.form.form_uuid} = [];
    """
    for table_id, table in self.form.tables.items():
      self.javascript += f"""tables_{self.form.form_uuid}['{table_id}'] = {json.dumps(table)};
      """

    # Ajoute les listeners pour affichage/masquage des champs en fonction des choix de l'utilisateur (modification de SELECT)
    self.javascript += "{select_array}".format(select_array=self.selects_with_triggers)
    self.javascript += """.forEach(selectId => {
      let select_element = document.getElementById('"""+self.form.form_uuid+"""_d_'+selectId);
      select_element.addEventListener('change', () => {
          update_form_visibility_"""+self.form.form_uuid+"""();
      });
    });
    
    function update_form_visibility_"""+self.form.form_uuid+"""() {"""
    for item_id in self.items_with_conditions:
      self.javascript += "update_visibility_"+self.form.form_uuid+'_d_'+item_id+"();"
    self.javascript += """
    }
    """
  
    # Ajoute le code Javascript appelé à l'initialisation du formulaire (mais aussi quand on clique sur le bouton de réinitialisation)
    self.javascript += "function initForm_"+self.form.form_uuid+"() {"
    for template_item in self.form.template:
      if template_item.get('on_load'):
        self.javascript += "cfiForm = new CfiForm('"+self.form.form_uuid+"', '"+template_item['id']+"'); "+template_item['on_load'] + ";";
        # ORG self.javascript += template_item['on_load'].format(formItem="'"+self.form.form_uuid+"'", inputItem="document.getElementById('"+self.form.form_uuid+'_d_'+template_item['id']+"')") + "\n"
    self.javascript += "}"
    self.javascript += "initForm_"+self.form.form_uuid+"();"
        
    # Ajoute les listener onchange
    for template_item in self.form.template:
      if template_item.get('on_change'):
        self.javascript += "document.getElementById('"+self.form.form_uuid+'_d_'+template_item['id']+"').addEventListener('change', () => { cfiForm = new CfiForm('"+self.form.form_uuid+"', '"+template_item['id']+"'); "+template_item['on_change']+"      });";
 
 
  def _generate_code_text(self, template_item:str):

    self._start_table()
  
    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'])

    clipboard_data = ''
    clipboard_html = ''
    if template_item.get('clipboard_category'):
      clipboard_data = ' data-clipboardcategory="'+html.escape(template_item['clipboard_category'])+'"'
      clipboard_html = """<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>"""

    copy_value_html = ''
    if template_item.get('copy_value'):
      copy_value_html = """<span class="cellimg"><img title="Copy value" onclick="copyFieldValue(this)" src="/images/copy.png"></span>"""
    

    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><input type="text" name="{field_id}" value="{value}" defaultValue="{value}" id="{input_uuid}" class="intable {form_uuid}" {disabled}{clipboard_data}{readonly}/></td><td>{clipboard_html}</td><td>{copy_value_html}</td></tr>'.format(
      form_uuid = self.form.form_uuid,
      tr_uuid = self.form.form_uuid+'_tr_'+template_item['id'],
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      label = self._row_label(template_item['label'], template_item['help_button'], template_item['id']), 
      field_id = html.escape(template_item['id']),
      value = html.escape(self.form.content.get(template_item['id'], '')),
      display = 'table-row' if display else 'none',
      disabled = 'disabled ' if not display else '',
      clipboard_data = clipboard_data,
      clipboard_html = clipboard_html,
      copy_value_html = copy_value_html,
      readonly = 'readonly' if template_item.get('readonly', False) else '',
      )
      
  
  def _generate_code_password(self, template_item:str):

    self._start_table()
  
    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'])

    clipboard_data = ''
    clipboard_html = ''
    if template_item.get('clipboard_category') and self.form.options['/clipboard/remember_secrets']:
      clipboard_data = ' data-clipboardcategory="'+html.escape(template_item['clipboard_category'])+'"'
      clipboard_html = """<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>"""

    copy_value_html = ''
    if template_item.get('copy_value'):
      copy_value_html = """<span class="cellimg"><img title="Copy value" onclick="copyFieldValue(this)" src="/images/copy.png"></span>"""
    

    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><input type="password" name="{field_id}" value="{value}" defaultValue="{value}" id="{input_uuid}" class="intable {form_uuid}" {disabled}{clipboard_data}{readonly}/></td><td>{clipboard_html}</td><td>{copy_value_html}</td></tr>'.format(
      form_uuid = self.form.form_uuid,
      tr_uuid = self.form.form_uuid+'_tr_'+template_item['id'],
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      label = self._row_label(template_item['label'], template_item['help_button'], template_item['id']), 
      field_id = html.escape(template_item['id']),
      value = html.escape(self.form.content.get(template_item['id'], '')),
      display = 'table-row' if display else 'none',
      disabled = 'disabled ' if not display else '',
      clipboard_data = clipboard_data,
      clipboard_html = clipboard_html,
      copy_value_html = copy_value_html,
      readonly = 'readonly' if template_item.get('readonly', False) else '',
      )
  
  
  def _generate_code_textarea(self, template_item:str):
    """
      Versions:
        03/12/2024 (mpham) la valeur était toujours vide
    """

    self._start_table()
  
    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'])

    clipboard_data = ''
    clipboard_html = ''
    if template_item.get('clipboard_category'):
      clipboard_data = ' data-clipboardcategory="'+html.escape(template_item['clipboard_category'])+'"'
      clipboard_html = """<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>"""

    copy_value_html = ''
    if template_item.get('copy_value'):
      copy_value_html = """<span class="cellimg"><img title="Copy value" onclick="copyFieldValue(this)" src="/images/copy.png"></span>"""
    

    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><textarea name="{field_id}" defaultValue="{value}" id="{input_uuid}" class="intable {form_uuid}" rows={rows} {disabled}{clipboard_data}{readonly}>{value}</textarea></td><td>{clipboard_html}</td><td>{copy_value_html}</td></tr>'.format(
      form_uuid = self.form.form_uuid,
      tr_uuid = self.form.form_uuid+'_tr_'+template_item['id'],
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      label = self._row_label(template_item['label'], template_item['help_button'], template_item['id']), 
      field_id = html.escape(template_item['id']),
      value = html.escape(self.form.content.get(template_item['id'], '')),
      rows = template_item['rows'],
      display = 'table-row' if display else 'none',
      disabled = 'disabled ' if not display else '',
      clipboard_data = clipboard_data,
      clipboard_html = clipboard_html,
      copy_value_html = copy_value_html,
      readonly = 'readonly' if template_item.get('readonly', False) else '',
      )
  
  
  def _generate_code_closed_list(self, template_item:str):

    self._start_table()

    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'])
    
    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><select id={input_uuid} name="{field_id}" class="intable {form_uuid}" {disabled}{readonly}/>'.format(
      form_uuid = self.form.form_uuid,
      tr_uuid = self.form.form_uuid+'_tr_'+template_item['id'],
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      label = self._row_label(template_item['label'], template_item['help_button'], template_item['id']), 
      field_id = html.escape(template_item['id']),
      display = 'table-row' if display else 'none',
      disabled = 'disabled ' if not display else '',
      readonly = 'readonly' if self.form.content.get(template_item['readonly'], False) else '',
      )

    for value, option_label in template_item['values'].items():
      selected = ''
      if value.casefold() == self.form.content.get(template_item['id'], template_item['default']).casefold():
        selected = ' selected'
      self.html += '<option value="'+value+'"'+selected+'>'+html.escape(option_label)+'</value>'
    self.html += '</td><td></td><td></td></tr>'


  def _generate_code_check_box(self, template_item:str):

    self._start_table()
  
    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'])

    self.html += '<tr id="{tr_uuid}" style="display: {display};"><td>{label}</td><td><input type="checkbox" name="{field_id}" {checked} id={input_uuid} class="{form_uuid}" {disabled}{readonly}/></td><td></td><td></td></tr>'.format(
      form_uuid = self.form.form_uuid,
      tr_uuid = self.form.form_uuid+'_tr_'+template_item['id'],
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      label = self._row_label(template_item['label'], template_item['help_button'], template_item['id']), 
      field_id = html.escape(template_item['id']),
      checked = 'checked ' if self.form.content.get(template_item['id'], False) else '',
      display = 'table-row' if display else 'none',
      disabled = 'disabled ' if not display else '',
      readonly = 'readonly' if template_item.get('readonly', False) else '',
      )
  
  def _generate_code_hidden(self, template_item:str):

    self.html += '<input type="hidden" name="{field_id}" value="{value}" id="{input_uuid}" class="intable {form_uuid}" />'.format(
      form_uuid = self.form.form_uuid,
      input_uuid = self.form.form_uuid+'_d_'+template_item['id'],
      field_id = html.escape(template_item['id']),
      value = html.escape(self.form.content.get(template_item['id'], '')),
      )
      
      
  def _generate_code_start_section(self, template_item:str):
    self._end_table()

    display = self._evaluate_display(template_item['displayed_when'])
    self._add_display_javascript(template_item['id'], template_item['displayed_when'], element_type='section')

    section_id = self.form.form_uuid+'_section_'+template_item['id']

    collapse_display = "block"
    collapse_html = ""
    if template_item['collapsible']:
      plus_display = 'none'
      minus_display = 'block'
      if template_item['collapsible_default']:
        collapse_display = 'none'
        plus_display = 'block'
        minus_display = 'none'
      collapse_html = '<img class="plus_button" src="/images/plus.png" title="Expand" style="display: {plus_display}" onclick="expandSection(\'{section_id}\')"><img class="minus_button" src="/images/moins.png" title="Collapse" style="display: {minus_display}" onclick="collapseSection(\'{section_id}\')">'.format(
        section_id = section_id,
        plus_display = plus_display,
        minus_display = minus_display,
        )

    self.html += '<div id="{section_id}" style="display: {display}; align-items: baseline;"><span style="width: 20px; display: inline-block;">{collapse}</span><span style="display: inline-block;"><h{header}>{title}</h{header}><span class="section_content" style="display: {collapse_display};">'.format(
      section_id = section_id,
      display = 'flex' if display else 'none',
      collapse = collapse_html,
      collapse_display = collapse_display,
      title = html.escape(template_item['label']), 
      header = template_item['level']+1
      )


  def _generate_code_end_section(self, template_item:str):
    self._end_table()
    self.html += '</span></span></div>'
    

  def _generate_code_raw_html(self, template_item:str):
    self.html += template_item['html']
  

  def _start_table(self):
    
    if not self.in_table:
      self.html += '<table class="fixed">'
      self.in_table = True
      

  def _end_table(self):
    
    if self.in_table:
      self.html += '</table>'
      self.in_table = False
      

  def _row_label(self, label:str='', help_button:bool=True, field_id:str=None):
    
    if help_button and field_id is not None:
      help_id = '/'+self.form.form_id+'/'+field_id
      row_label = '<span class="celltxt">{label}</span><span class="cellimg"><img onclick="help(this, \'{help_id}\')" src="/images/help.png"></span>'.format(label=html.escape(label), help_id=html.escape(help_id))
    else:
      row_label = html.escape(label)
      
    return row_label
    
  
  def _evaluate_display(self, condition:str) -> bool:
    
    proposition = Proposition(condition)
    display = proposition.eval(self.form.content)

    for select_id in proposition.variables:
      if select_id not in self.selects_with_triggers:
        self.selects_with_triggers.append(select_id)
    
    return display
    
    
  def _add_display_javascript(self, field_id:str, condition:dict, element_type:str='tr') -> str:
  
    if condition != 'True' and condition != 'False' :

      proposition = Proposition(condition)
      js_condition = proposition.transpose_javascript(lambda var: "document.getElementById('" + self.form.form_uuid+'_d_'+var + "').value")

      if element_type == 'tr':
        display_value = 'table-row'
      elif element_type == 'section':
        display_value = 'flex'
      else:
        display_value = 'block'

      # ajuste la visibilité des champs (et activation des INPUT) en fonction des SELECT
      #   appelés lorsque l'utilisateur change un SELECT
      self.javascript += """
      function update_visibility_"""+self.form.form_uuid+'_d_'+html.escape(field_id)+"""() {
        let el_id = '"""+self.form.form_uuid+'_'+element_type+'_'+html.escape(field_id)+"""';
        let styleDisplay = 'none';
        let disabled = true;
        if ("""+js_condition+""") {
          styleDisplay = '"""+display_value+"""';
          disabled = false;
        }
        document.getElementById(el_id).style.display = styleDisplay;
        Array.from(document.getElementById(el_id).getElementsByTagName('input')).forEach(element => {
          element.disabled = disabled;
        });
        Array.from(document.getElementById(el_id).getElementsByTagName('select')).forEach(element => {
          element.disabled = disabled;
        });

      }
      """
      
      self.items_with_conditions.append(field_id)
      
      
class RequesterForm(CfiForm):
  
  def __init__(self, form_id:str, content:dict, request_url:str, action:str=None, mode:str='new_page', submit_label:str=None):
    """ Constructeur
    
    Une requêteur HTTP a deux comportements possibles :
      - new_page : mode normal où la requête est envoyée pour remplacer la page du navigateur
      - api : ClientFedID réalise un appel de type service web et affiche le résultat dans la même page que la requête
    
    L'URL request_url est celle à laquelle la requête doit être envoyée
    
    Différente de l'URL interne qui doit réaliser l'opération (senderUrl)
    
    On indique que l'URL est à récupérer dans le formulaire en donnant : @field_id
    Par exemple : @token_endpoint
    
    Par défaut les informations nécessaires à l'exécution de la requête sont envoyées à /client/httprequester/sendrequest (en mode API)
    On peut les envoyer à un autre point d'accès de ClientFedID par le paramètre action
    
    Args:
      form_id: identifiant du formulaire, utilisé essentiellement pour indexation de l'aide en ligne
      content: dictionnaire de données donnant la valeur d'initialisation des champs
        clé : identifiant du champ
        valeur : type simple avec la valeur du champ (str ou bool)
      request_url: URL cible de la requête, donnée directement (en https://) ou en référence à la valeur d'un champ (@field_id)
      action: URL recevant les informations du formulaire, pour envoi des données à request_url
        si pas donnée, le comportement dépend du mode
          en new_page, on ne met pas d'action (formulaire envoyé à la même URL)
          en api, le formulaire est envoyé à /client/httprequester/sendrequest
      mode: indique comment le formulaire est envoyé
        - new_page : mode normal où la réponse remplace la page
        - api : la requête est effectuée par ClientFedID en service web et la réponse est ajoutée dans la page courante, juste après le formulaire
      submit_label: libellé du bouton de soumission du formulaire
      
    Versions:
      28/12/2023 (mpham) version initiale, adaptée de FlowHandler.display_form_http_request
      24/08/2024 (mpham) ajout des modifying_fields : champs qui ne font pas partie de la requête finale mais dont le changement
                           en entraîne une modification
    """
    
    super().__init__(form_id, content, action, mode, submit_label)
    self.mode = mode
    self.title = None
    if self.action is None:
      if self.mode == 'new_page':
        self.action = '/client/httprequester/sendrequest'
    self.request_parameters = {}
    self.modifying_fields = None
    self.http_parameters = {
      'request_url': request_url,
      'form_method': 'post',
      'body_format': 'x-www-form-urlencoded',
      'auth_method': 'none',
      'auth_login_param': 'client_id',
      'auth_secret_param': 'client_secret',
      'verify_certificates': True,
      }
    self.visible_requester_fields = {
      'request_url': True,
      'request_data': True,
      'form_method': False,
      'auth_method': True,
      'auth_login': True,
      'auth_secret': True,
      'auth_login_param': False,
      'auth_secret_param': False,
      'verify_certificates': True,
      }
    self.data_generator = None
    
    self._requester_appened = False


  def set_request_parameters(self, request_parameters:dict, modifying_fields:list=None):
    """ Donne les paramètres composant la requête finale
    
    Ces paramètres contiennent la plupart du temps des références à des valeurs du formulaire.
      On les indique par @[<identifiant du champ de formulaire>]
    
    La modification de ces champs déclenche la mise à jour de la requête (URL en GET et data en POST et REDIRECT).
    
    Si aucun data_generator n'est donné, le comportement par défaut est de générer une requête automatiquement à partir des paramètres donnés.
    
    Args
      request_parameters: dict avec les paramètres de la requête
        clé : nom du paramètre tel qu'il figurera dans la requête finale
        valeur : chaîne pouvant contenir des références à des valeurs de champs, données par @[field_id]
        None si la requête n'admet pas de paramètres
      modifying_fields: list des champs dont la modification déclenche une modification de la requête finale à envoyer
        (qui s'affiche dans le requêteur). Ne mettre que les champs qui ne font pas partie de la requête finale.
    
    Versions:
      30/12/2023 (mpham) version initiale
      09/08/2024 (mpham) possibilité de ne pas envoyer de paramètres (simple GET sans query string)
      25/08/2024 (mpham) ajout des modifying_fields
    """
    self.request_parameters = request_parameters
    self.modifying_fields = modifying_fields
    

  def modify_http_parameters(self, http_parameters:dict):
    """ Modifie des paramètres HTTP
    
    Les paramètres sont les suivants :
      form_method: post, get ou redirect (302). redirect n'est possible qu'en mode new_page
        par défaut post
      body_format: format du corps de la requête finale, possible uniquement en POST et en REDIRECT
        x-www-form-urlencoded: formulaire web classique (défaut)
        json: document JSON
      auth_method: none, basic, form, bearer_token
        par défaut la requête n'est pas authentifiée
        form ajoute le login et le mot de passe dans les valeurs du formulaire
        basic et bearer_token sont passés dans l'en-tête Authorization
      auth_login: login ou jeton, pour récupérer la valeur d'un champ du formulaire, mettre par exemple @['client_id']
      auth_secret: mot de passe
      verify_certificates: booléen indiquant le requêteur HTTP doit vérifier le certificat présenté par le serveur
      
    Toutes les valeurs des paramètres peuvent être récupérées depuis le formulaire, par @field_id (par exemple @verify_certificates)
    
    Args:
      http_parameters: liste des paramètres à changer. Une clé du dict donné en paramètre dont la valeur est None est retirée de la configuration
    
    Versions:
      28/12/2023 (mpham) version initiale
    """
    for key, value in http_parameters.items():
      if value is None:
        self.http_parameters.pop(key, None)
      else:
        self.http_parameters[key] = value
    

  def modify_visible_requester_fields(self, visible_requester_fields:dict):
    """ Indique les champs du requêteur HTTP qui doivent être affichés
    
    Ces champs sont :
      request_url: URL finale
      request_data: corps de la requête
      body_format: encodage du corps (x-www-form-urlencoded ou JSON)
      form_method: méthode d'envoi (POST, GET ou REDIRECT)
      auth_method: méthode d'authentification
      auth_login: login
      auth_secret: mot de passe (affiché en fonction de la méthode d'authentification)
      verify_certificates: vérification du certificat du serveur

    Args:
      visible_requester_fields: dictionnaire avec les champs dont la visibilité est à modifier, avec True ou False en valeur
    
    Versions:
      28/12/2023 (mpham) version initiale
    """
    for key, value in visible_requester_fields.items():
      self.visible_requester_fields[key] = value

  
  def set_data_generator_code(self, code:str):
    """ 

    Les données de la requête sont mises à jour automatiquement lorsque des valeurs des <input> dont l'identifiant commence par <self.form.form_uuid>_ sont modifiées (par exemple 424986_scope
    Pour cela, il doit être fourni le code Javascript de génération, qui retourne (dans return) les données.
      Dans ce code, les valeurs sont récupérées par la fonction getFormValue qui prend en argument l'identifiant de l'<input> sans le dom
    
    Le tableau asociatif paramValues contient les valeurs des champs définis par set_request_parameters. Ce tableau peut être modifiée et retourné.
    
    Les champs de formulaire sont récupérables par cfiForm.getField('scope')
      Pour avoir la valeur du champ, on fait cfiForm.getField('scope').value
    
    Par exemple :
      data = {'scope': cfiForm.getField('scope').value};
      return data;
      
    En utilisant paramValues :
      delete paramValues['scope'];
      return paramValues;
      
    Ces informations sont mises dans le corps en POST et REDIRECT, et en query string en GET.
    
    Versions:
      28/12/2023 (mpham) version initiale
    """
    self.data_generator = code
    
  
  def _generate_code(self):
    """
    Versions:
      09/08/2024 (mpham) les requêtes peuvent ne pas avoir de paramètres
      24/08/2024 (mpham) mise à disposition de cfiForm dans le request data generator
      24/08/2024 (mpham) ajout des modifying_fields indiquant les champs qui déclenchent une modification de la requête
      27/11/2024 (mpham) prise en compte de l'option /requester/include_empty_items qui permet de ne pas inclure dans le contenu du formulaire les valeurs vides
    """

    self._append_requester()

    self.content['hr_request_url'] = self.http_parameters.get('request_url', '')
    self.content['hr_form_method'] = self.http_parameters.get('form_method', 'post')
    self.content['hr_body_format'] = self.http_parameters.get('body_format', 'x-www-form-urlencoded')
    self.content['hr_auth_method'] = self.http_parameters.get('auth_method', 'none')
    self.content['hr_verify_certificates'] = self.http_parameters.get('verify_certificates', True)

    code_generator = CodeGenerator(self)
    code_generator.generate()
    self.html = code_generator.html
    self.javascript = code_generator.javascript
    
    # code Javascript pour mise à jour dynamique de la requête finale
    
    # listeners sur les champs du formulaire déclenchant la mise à jour automatiquement
    
    # la fonction Javascript updateRequest_<form_uuid> déclenche les actions suivantes :
    #   - mise à jour des champs du requêteur (hors request data / query string) en fonction des champs du formulaire
    #   - calcul de request data (pour POST et REDIRECT) ou de la query string (pour GET) dans ce dernier cas l'URL est aussi modifiée pour lui ajouter la query string
    # On a donc besoin de listeners sur les champs du formulaire pour ces deux utilisations
    #
    # Listeners pour mise à jour des champs du requêteur :
    #   on interprète les http_parameters qui donnent les valeurs des champs pour en extraire les champs du formulaire qui y sont référencés
    # Listeneurs de request data
    #   on regarde request_parameters si donné
    #   sinon on prend tous les champs du formulaire puisque la requête finale est alors construite avec tous les champs
    
    listener_fields = []
    if self.modifying_fields:
      listener_fields = self.modifying_fields

    # ajout des champs du formulaire modifiant le requêteur
    listener_fields.extend(self._find_variables_from_expressions(self.http_parameters.values()))
    
    # ajout des champs du formulaire utilisés pour construire les données de la requête
    if self.request_parameters == {}:
      # tous les champs déclenchent une modification
      for template_item in self.template:
        if template_item['holds_value'] and not template_item['id'].startswith('hr'):
          if template_item['id'] not in listener_fields:
            listener_fields.append(template_item['id'])
    elif self.request_parameters is None:
      # Requête sans paramètres
      pass
    else:
      parameters_listener_fields = self._find_variables_from_expressions(self.request_parameters.values())
      for field_id in parameters_listener_fields:
        if field_id not in listener_fields:
          listener_fields.append(field_id)
      
    # mise en place des listeners
    indexed_template = {}
    for template_item in self.template:
      indexed_template[template_item['id']] = template_item
    
    for field_id in listener_fields:
      template_item = indexed_template.get(field_id)
      if template_item is None:
        raise DesignError("unknown field {field_id}".format(field_id=field_id))
      event = 'change'
      if template_item['type'] in ['text', 'password', 'textarea']:
        event = 'keyup'
      js = """document.getElementById('"""+self.form_uuid+'_d_'+html.escape(field_id)+"""').addEventListener('"""+event+"""', () => {
        updateRequest_"""+self.form_uuid+"""();
      });
      """
      self.javascript += js
    
    # Javascript de mise à jour
    self.javascript += """
    function updateRequest_"""+self.form_uuid+"""() {
    
      // Valeurs des champs du requêteur
      let requesterFieldValues = {};
    """
    for param, value in self.http_parameters.items():
      self.javascript += """requesterFieldValues."""+param+""" = """+self.transpose_expression_to_javascript(value)+""";
      """
    
    self.javascript += """
      // Valeurs des paramètres
      let paramValues = {};
    """
    if self.request_parameters == {}:
      # on met tous les champs en paramètres
      for template_item in self.template:
        if template_item['holds_value'] and not template_item['id'].startswith('hr'):
          self.javascript += """
      paramValue = getFormValue('"""+self.form_uuid+"""', '"""+template_item['id']+"""');
      """
          if not self.options['/requester/include_empty_items']:
            self.javascript += """
              if (paramValue != '') {
              """
          self.javascript += """
            paramValues."""+template_item['id']+""" = paramValue;
            """
          if not self.options['/requester/include_empty_items']:
            self.javascript += """
              }
              """
    elif self.request_parameters is None:
      # Requête sans paramètres
      pass
    else:
      # les paramètres sont été donnés par set_request_parameters()
      for param, value in self.request_parameters.items():
        self.javascript += """
          paramValue = """+self.transpose_expression_to_javascript(value)+""";
          """
        if not self.options['/requester/include_empty_items']:
          self.javascript += """
            if (paramValue != '') {
            """
        self.javascript += """
          paramValues."""+param+""" = paramValue;
        """
        if not self.options['/requester/include_empty_items']:
          self.javascript += """
            }
            """

    if self.data_generator:
      # on a fourni du code Javascript pour retraiter les données
      self.javascript += """
        paramValues = transformData_"""+self.form_uuid+"""(paramValues);
      """
      
    self.javascript += """
      updateFormData('"""+self.form_uuid+"""', requesterFieldValues, paramValues);
    }
    """
    
    if self.data_generator:
      # on a fourni du code Javascript pour retraiter les données
      self.javascript += """
    function transformData_"""+self.form_uuid+"""(paramValues) {
      cfiForm = new CfiForm('"""+self.form_uuid+"""', null);
      """+self.data_generator+"""
      }
      """
    
    # on met à jour les données dynamiques du formulaire : champs du requêteur
    self.javascript += """
    updateRequest_"""+self.form_uuid+"""();
    """
    
    # Bouton Modify request
    self.javascript += """document.getElementById('"""+self.form_uuid+'_modify_request'+"""').addEventListener('change', () => {
        updateModifyRequest('"""+self.form_uuid+"""');
      });
      updateModifyRequest('"""+self.form_uuid+"""');
      """
    
    
  def _find_variables_from_expressions(self, expressions:list) -> list:
    """ Identifie les variables dans les expressions d'une liste
    
    Une variable est écrite en @[variable] dans les valeurs
    
    Args:
      dictionnary: dict dont les valeurs sont analysées
      
    Versions:
      30/12/2023 (mpham) version initiale
    """
    
    variables = []
  
    # on va chercher les champs comme références dans self.request_parameters
    for value in expressions:
      if isinstance(value, str):
      
        arobase_pos = value.find('@[')
        while arobase_pos >= 0:
          variable_end_pos = value.find(']', arobase_pos)
          if variable_end_pos == -1:
            raise DesignError("missing closing bracket at position {position} in {string}".format(string=value, position=arobase_pos))
          field_id = value[arobase_pos+2:variable_end_pos]
          if field_id not in variables:
            variables.append(field_id)
          arobase_pos = value.find('@[', variable_end_pos)

    return variables


  def transpose_expression_to_javascript(self, expression) -> str:
    """ Traduit une expression avec des références à des champs en Javascript
    
    Une expression peut être :
       une chaîne contenant des références vers des valeurs de champs dans le formulaire
       un booléen
    
    Par exemple : "openid @[scopes]"
    
    Cette expression donne en Javascript : "openid "+getFormValue('<formUUID>', 'scope')
    
    Args:
      expression: un expression avec des variables
      
    Versions:
      30/12/2023 (mpham) version initiale
    """

    js = ''
    
    if isinstance(expression, bool):
      
      js = 'true' if expression else 'false'
    
    elif isinstance(expression, str):
    
      current_pos = 0
      arobase_pos = expression.find('@[')
      while arobase_pos >= 0:
        variable_end_pos = expression.find(']', arobase_pos)
        if variable_end_pos == -1:
          raise DesignError("missing closing bracket at position {position} in {string}".format(string=expression, position=arobase_pos))
        field_id = expression[arobase_pos+2:variable_end_pos]
        js += '"' + expression[current_pos:arobase_pos].replace('"', '\\"') + """" + getFormValue('"""+self.form_uuid+"""', '"""+field_id+"""') + """
        
        current_pos = variable_end_pos+1
        arobase_pos = expression.find('@[', variable_end_pos+1)
      js += '"' + expression[current_pos:].replace('"', '\\"') + '"'
      
    else:
      raise DesignError("unknown type for expression {expression}".format(expression=expression))
    
    return js


  def send_form(page_handler, hr_data:dict, default_secret=None):
    """ Envoie une requête préparée par un RequesterForm
    
      Args:
        hr_data: le formulaire tel qu'il a été reçu depuis un RequesterForm en mode API
        default_secret: secret à utiliser s'il n'a pas été saisi dans le formulaire
        
      Returns:
        réponse de requests
    
      Versions:
        09/08/2024 (mpham) version initiale adaptée de FlowHandler.send_form_http_request
        05/09/2024 (mpham) POST ne fonctionnait pas
        27/11/2024 (mpham) les checkbox, donc en particulier la vérification des certificats, ont le même comportement que les formulaires
                             l'élement est présent si la case est cochée, absent sinon
    """
    
    service_endpoint = hr_data.get('hr_request_url')
    if not service_endpoint:
      raise AduneoError(self.log_error("RequesterForm sender was called without a service URL in hr_request_url field"))
      
    page_handler.log_info(f"Sending HTTP request to {service_endpoint}")
    
    # méthode HTTP de la requête à envoyer
    method = hr_data.get('hr_form_method')
    if not method:
      raise AduneoError(page_handler.log_error("HTTP method not found in hr_form_method field"))
    page_handler.log_info("  HTTP method "+method)

    service_data = hr_data.get('hr_request_data', '')
      
    auth_method = hr_data.get('hr_auth_method')
    if not auth_method:
      raise AduneoError(page_handler.log_error("Call authentication method not found in request"))
    
    auth_login = hr_data.get('hr_auth_login', '')
    auth_secret = hr_data.get('hr_auth_secret', '')
    if auth_secret == '':
      auth_secret = default_secret
      
    request_auth = None
    request_headers = {}
    if auth_method.casefold() == 'basic':
      request_auth = (auth_login, auth_secret)
    elif auth_method.casefold() == 'post':
      login_param = hr_data.get('hr_auth_login_param')
      if not login_param:
        raise AduneoError(page_handler.log_error("Form parameter for login not found in hr_auth_login_param field"))
      service_data[login_param] = auth_login
      secret_param = hr_data.get('hr_auth_secret_param')
      if not secret_param:
        raise AduneoError(page_handler.log_error("Form parameter for secret not found in hr_auth_secret_param field"))
      service_data[secret_param] = auth_secret
    elif auth_method.casefold() == 'bearer_token':
      request_headers = {'Authorization':"Bearer "+auth_login}
    else:
      raise AduneoError(page_handler.log_error("authentication method "+auth_method+" not supported"))

    verify_cert = hr_data.get('hr_verify_certificates') != None

    page_handler.log_info("  Submitting request")
    try:
      page_handler.log_info(('  ' * 1)+"Connecting to "+service_endpoint)
      page_handler.log_info(('  ' * 1)+'Certificate verification: '+("enabled" if verify_cert else "disabled"))
      page_handler.log_info(f"{'  ' * 1}Authentication {auth_method} with login {auth_login}")
      if method == 'get':
        response = requests.get(service_endpoint, headers=request_headers, auth=request_auth, verify=verify_cert)
      elif method == 'post':
        page_handler.log_info(f"{'  ' * 1}Body: {service_data}")
        body_format = hr_data.get('hr_body_format', 'x-www-form-urlencoded')
        if  body_format == 'x-www-form-urlencoded':
          request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
          response = requests.post(service_endpoint, data=service_data, headers=request_headers, auth=request_auth, verify=verify_cert)
        elif body_format == 'json':
          request_headers['Content-Type'] = 'application/json'
          response = requests.post(service_endpoint, json=service_data, headers=request_headers, auth=request_auth, verify=verify_cert)
        else:
          raise AduneoError(f"body format {body_format} not supported")
      else:
        raise AduneoError(page_handler.log_error("HTTP method "+method+" not supported"))
    except Exception as error:
      raise AduneoError(page_handler.log_error(('  ' * 1)+'http service error: '+str(error)))
    if response.status_code != 200:
      raise AduneoError(page_handler.log_error('http service error: status code '+str(response.status_code)+", "+response.text))
      
    return response

    
  def _append_requester(self):
    """ Ajoute le requester HTTP
    
      Versions:
        00/12/2023 (mpham) version initiale
        30/08/2024 (mpham) liste des méthodes d'authentification dans l'option /requester/auth_method_options
        03/12/2024 (mpham) les champs auth_login et auth_secret ne sont plus affichés en authentification de type form
    """
    
    if not self._requester_appened:

      self.hidden('hr_context')
      
      http_methods = {'post': 'POST', 'get': 'GET'}
      if self.mode == 'new_page':
        http_methods['redirect'] = 'REDIRECT'
      
      displayed_when_dict = {
        'hr_request_url': "True",
        'hr_form_method': "True",
        'hr_body_format': "@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect'",
        'hr_request_data': "@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect'",
        'hr_auth_method': "True",
        'hr_auth_login': "@[hr_auth_method] = 'basic' or @[hr_auth_method] = 'bearer_token'",
        'hr_auth_secret': "@[hr_auth_method] = 'basic'",
        'hr_auth_login_param': "@[hr_auth_method] = 'form' and (@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect')",
        'hr_auth_secret_param': "@[hr_auth_method] = 'form' and (@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect')",
        'hr_verify_certificates': "True",
      }

      for field, visibility in self.visible_requester_fields.items():
        if not visibility:
          displayed_when_dict['hr_'+field] = "False"

      auth_method_options = self.options['/requester/auth_method_options']
      if not auth_method_options:
        auth_method_options = ['none', 'basic', 'form', 'bearer_token']
      auth_method_select = {value: {'none': 'None', 'basic': 'Basic', 'form': 'Form', 'bearer_token': 'Bearer Token'}[value] for value in auth_method_options}
      
      section_title = 'HTTP request' + (' for '+self.title if self.title else '')
      self.start_section('http_requester', title=section_title, level=2) \
        .raw_html('<div class="intertable"><label for="{input_id}">Modify request</label><input type="checkbox" id={input_id} name="modify_request" /></div>'.format(input_id=self.form_uuid+"_modify_request")) \
        .textarea('hr_request_url', label='URL', rows=1, displayed_when=displayed_when_dict['hr_request_url'], clipboard_category='request_url') \
        .closed_list('hr_form_method', label='HTTP Method', displayed_when=displayed_when_dict['hr_form_method'], 
          values=http_methods,
          default = 'post',
          ) \
        .closed_list('hr_body_format', label='Request data format', displayed_when=displayed_when_dict['hr_body_format'], 
          values={'x-www-form-urlencoded': 'x-www-form-urlencoded', 'json': 'JSON'},
          default = 'post'
          ) \
        .textarea('hr_request_data', label='Request data', displayed_when=displayed_when_dict['hr_request_data']) \
        .closed_list('hr_auth_method', label='HTTP authentication', displayed_when=displayed_when_dict['hr_auth_method'], 
          values = auth_method_select,
          default = 'None'
          ) \
        .text('hr_auth_login', label='HTTP login', clipboard_category='client_id', displayed_when=displayed_when_dict['hr_auth_login']) \
        .text('hr_auth_login_param', label='Login parameter name', displayed_when=displayed_when_dict['hr_auth_login_param']) \
        .password('hr_auth_secret', label='HTTP secret', clipboard_category='client_secret', displayed_when=displayed_when_dict['hr_auth_secret']) \
        .text('hr_auth_secret_param', label='Secret parameter name', displayed_when=displayed_when_dict['hr_auth_secret_param']) \
        .check_box('hr_verify_certificates', label='Verify certificates', displayed_when=displayed_when_dict['hr_verify_certificates']) \
      .end_section()

    
    
      