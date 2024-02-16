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
  
  Versions:
    27/12/2023 (mpham) version initiale
  """

  def __init__(self, form_id:str, content:dict, action:str=None, mode:str='new_page'):
    """ Constructeur
    
    Args:
      form_id: identifiant du formulaire, essentiellement utiliser pour les codes d'affichage de l'aide en ligne
      content: dict à plat contenant les valeurs par défaut des champs
      action: URL où envoyer le formulaire
      mode: indique comment le formulaire est envoyé
        - new_page : mode normal où la réponse remplace la page
        - api : la requête est effectuée par ClientFedID en service web et la réponse est ajoutée dans la page courante, juste après le formulaire
    
    Versions:
      27/12/2023 (mpham) version initiale
    """
  
    self.form_id = form_id
    self.action = action
    self.mode = mode
    self.form_uuid = 'i'+str(uuid.uuid4()).replace('-', '_') # car on utilise dom_id dans le nom de fonctions Javascript, et document.querySelectorAll n'aime pas les classes commençant par un chiffre

    # Template (construit par les méthodes text(), closed_list(), check_box(), etc.)
    self.template = []
    
    # Contenu
    self.title = None
    self.content = content
    
    # Pour génération HTML et Javascript
    self.html = None
    self.javascript = None 
    self.selects_with_triggers = []
    self.items_with_conditions = []
    self.in_table = False
    
    # Options : /clipboard/remember_secrets uniquement
    self.options = {
      '/clipboard/remember_secrets': False,
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


  def closed_list(self, field_id:str, label:str='', values:dict={}, default:str='', help_button:bool=True, displayed_when:str="True", readonly:bool=False):

    closed_list = self._add_template_item('closed_list', field_id, label, help_button, displayed_when, readonly)
    closed_list['values'] = values
    closed_list['default'] = default
    return self


  def hidden(self, field_id:str):
  
    self._add_template_item('hidden', field_id)
    return self
  
  
  def check_box(self, field_id:str, label:str='', help_button:bool=True, displayed_when:str="True", readonly:bool=False):
  
    self._add_template_item('check_box', field_id, label, help_button, displayed_when, readonly)
    return self
  
  
  def start_section(self, section_id:str, title:str, help_button:bool=True, level:int=1):

    section = self._add_template_item('start_section', section_id, title, help_button, {}, holds_value=False)
    section['level'] = level
    return self


  def end_section(self):
    self._add_template_item('end_section', None, '', False, {}, holds_value=False)
    return self


  def raw_html(self, html:str):
    raw_html = self._add_template_item('raw_html', None, '', False, {}, holds_value=False)
    raw_html['html'] = html
    return self


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
      self.html += '<span class="middlebutton" onClick="document.getElementById(\'form-'+html.escape(self.form.form_uuid)+'\').submit();">Send request</span>'
    else:
      self.html += '<span class="middlebutton" onClick="sendToRequester(\''+html.escape(self.form.form_uuid)+'\')">Send request</span>'
    
    #self.html += '<span class="middlebutton" onClick="cancelRequest(\''+html.escape(self.form.form_uuid)+'\', \''+html.escape(context)+'\')">Cancel</span>'
    self.html += '</div>'
    self.html += '<div id="'+html.escape(self.form.form_uuid)+'_send_notification" style="display: none;">'
    self.html += '<h3>Sending request...</h3>'
    self.html += '</div>'
    
    
    self.html += '</form>'

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
        self.javascript += template_item['on_load'].format(formItem="'"+self.form.form_uuid+"'", inputItem="document.getElementById('"+self.form.form_uuid+'_d_'+template_item['id']+"')") + "\n"
    self.javascript += "}"
    self.javascript += "initForm_"+self.form.form_uuid+"();"
        
    

  
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
    

    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><textarea name="{field_id}" value="{value}" defaultValue="{value}" id="{input_uuid}" class="intable {form_uuid}" rows={rows} {disabled}{clipboard_data}{readonly}></textarea></td><td>{clipboard_html}</td><td>{copy_value_html}</td></tr>'.format(
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

    self.html += '<tr id={tr_uuid} style="display: {display}"><td>{label}</td><td><input type="checkbox" name="{field_id}" {checked} id={input_uuid} class="{form_uuid}" {disabled}{readonly}/></td><td></td><td></td></tr>'.format(
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
    self.html += '<h{header}>{title}</h{header}>'.format(title=html.escape(template_item['label']), header=template_item['level']+1)


  def _generate_code_end_section(self, template_item:str):
    self._end_table()
  

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
      help_id = self.form.form_id+'_'+field_id
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
    
    
  def _add_display_javascript(self, field_id:str, condition:dict) -> str:
  
    if condition != 'True' and condition != 'False' :

      proposition = Proposition(condition)
      js_condition = proposition.transpose_javascript(lambda var: "document.getElementById('" + self.form.form_uuid+'_d_'+var + "').value")

      # ajuste la visibilité des champs (et activation des INPUT) en fonction des SELECT
      #   appelés lorsque l'utilisateur change un SELECT
      self.javascript += """
      function update_visibility_"""+self.form.form_uuid+'_d_'+html.escape(field_id)+"""() {
        let tr_id = '"""+self.form.form_uuid+'_tr_'+html.escape(field_id)+"""';
        let styleDisplay = 'none';
        let disabled = true;
        if ("""+js_condition+""") {
          styleDisplay = 'table-row';
          disabled = false;
        }
        document.getElementById(tr_id).style.display = styleDisplay;
        Array.from(document.getElementById(tr_id).getElementsByTagName('input')).forEach(element => {
          element.disabled = disabled;
        });
        Array.from(document.getElementById(tr_id).getElementsByTagName('select')).forEach(element => {
          element.disabled = disabled;
        });

      }
      """
      
      self.items_with_conditions.append(field_id)
      
      
class RequesterForm(CfiForm):
  
  def __init__(self, form_id:str, content:dict, request_url:str, action:str=None, mode:str='new_page'):
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
      
    Versions:
      28/12/2023 (mpham) version initiale, adaptée de FlowHandler.display_form_http_request
    """
    
    super().__init__(form_id, content, action, mode)
    self.mode = mode
    self.title = None
    if self.action is None:
      if self.mode == 'new_page':
        self.action = '/client/httprequester/sendrequest'
    self.request_parameters = {}
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


  def set_request_parameters(self, request_parameters:dict):
    """ Donne les paramètres composant la requête finale
    
    Ces paramètres contiennent la plupart du temps des références à des valeurs du formulaire.
      On les indique par @[<identifiant du champ de formulaire>]
    
    La modification de ces champs déclenche la mise à jour de la requête (URL en GET et data en POST et REDIRECT).
    
    Si aucun data_generator n'est donné, le comportement par défaut est de générer une requête automatiquement à partir des paramètres donnés.
    
    Args
      request_parameters: dict avec les paramètres de la requête
        clé : nom du paramètre tel qu'il figurera dans la requête finale
        valeur : chaîne pouvant contenir des références à des valeurs de champs, données par @[field_id]
    
    Versions:
      30/12/2023 (mpham) version initiale
    """
    self.request_parameters = request_parameters
    

  def modify_http_parameters(self, http_parameters:dict):
    """ Modifie des paramètres HTTP
    
    Les paramètres sont les suivants :
      form_method: post, get ou redirect (302). redirect n'est possible d'en mode new_page
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
    
    Par exemple :
      data = {'scope': getFormValue(domId, 'scope')};
      return data;
      
    Ces informations sont mises dans le corps en POST et REDIRECT, et en query string en GET.
    
    Versions:
      28/12/2023 (mpham) version initiale
    """
    self.data_generator = code
    
  
  def _generate_code(self):

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

    # ajout des champs du formulaire modifiant le requêteur
    listener_fields = self._find_variables_from_expressions(self.http_parameters.values())
    
    # ajout des champs du formulaire utilisés pour construire les données de la requête
    if self.request_parameters == {}:
      # tous les champs déclenchent une modification
      for template_item in self.template:
        if template_item['holds_value'] and not template_item['id'].startswith('hr'):
          if template_item['id'] not in listener_fields:
            listener_fields.append(template_item['id'])
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
      paramValues."""+template_item['id']+""" = getFormValue('"""+self.form_uuid+"""', '"""+template_item['id']+"""');
      """
    else:
      # les paramètres sont été donnés par set_request_parameters()
      for param, value in self.request_parameters.items():
        self.javascript += """paramValues."""+param+""" = """+self.transpose_expression_to_javascript(value)+""";
        """

    if self.data_generator:
      # on a fourni du code Javascript pour retraiter les données
      self.javascript += """
        paramValues = transformData_"""+self.form_uuid+"""(paramValues);
      }
      """
      
    self.javascript += """
      updateFormData('"""+self.form_uuid+"""', requesterFieldValues, paramValues);
    }
    """
    
    if self.data_generator:
      # on a fourni du code Javascript pour retraiter les données
      self.javascript += """
    function transformData_"""+self.form_uuid+"""(paramValues) {
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


    
    
    #print(self.javascript)
    
  def dummy():
    # Formulaire technique
    self.html += "<h3>HTTP request for "+table['title']+"</h3>"

    if not http_parameters:
      http_parameters = {}
    default_http_parameters = {
        'auth_method': 'None',
        'auth_login': '',
        'url_label': None,
        'url_clipboard_category': None,
        }
    for item in default_http_parameters:
      if item not in http_parameters:
        http_parameters[item] = default_http_parameters[item]

    if self.sender_url:
      self.html += '<input id="'+html.escape(dom_id)+'_sender_url" type="hidden" value="'+html.escape(self.sender_url)+'" />'
      self.html += '<input id="'+html.escape(dom_id)+'_context" type="hidden" value="'+html.escape(context)+'" />'
    
    self.html += '<table class="fixed">'

    clipboard = ''
    if http_parameters:
      clipboard_category = http_parameters.get('url_clipboard_category')
      if clipboard_category:
        clipboard = ' data-clipboardcategory="'+html.escape(clipboard_category)+'"'
    self.html += '<tr><td>'+self.row_label('Request URL' if http_parameters['url_label'] == None else http_parameters['url_label'], 'request_url')+'</td><td><input id="'+html.escape(dom_id)+'_d_url" value="'+html.escape(url)+'" defaultValue="'+html.escape(url)+'" class="intable" type="text"'+clipboard+'></td>'
    self.html += '<td>'
    if clipboard != '':
      self.html += '<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>'
    self.html += '</td>'
    self.html += '</td></tr>' # TODO : il n'y a pas un </td> en trop ?
    
    methods = [m.strip().upper() for m in method.split(',')]
    for m in methods:
      if m not in ['GET','POST']:
        raise AduneoError(self.log_error("HTTP method "+m+" not supported"))
    if len(methods) == 1:
      # une seule méthode, on passe en champ masqué
      self.html += '<input id="'+html.escape(dom_id)+'_method" type="hidden" value="'+html.escape(method)+'" />'
    else:
      # l'utilisateur peut choisir la méthode
      self.html += '<tr><td>HTTP method</td><td><select id="'+html.escape(dom_id)+'_method" class="intable" onchange="f_'+dom_id+'_update()">'
      for m in methods:
        self.html += '<option value="'+html.escape(m)+'">'+html.escape(m)+'</option>'
      self.html += '</td></tr>'
    
    self.html += '<tr id="'+html.escape(dom_id)+'_tr_request_data"><td>'+self.row_label('Request data', 'request_data')+'</td><td><textarea id="'+html.escape(dom_id)+'_d_data" rows="4" class="intable"></textarea></td><td></td></tr>'

    # HTTP authentification is only displayed when calling an API
    if self.sender_url:
      self.html += '<tr><td>'+self.row_label('Call authentication', 'http_authentication')+'</td><td><select id="'+html.escape(dom_id)+'_d_auth_method" defaultValue="'+html.escape(http_parameters['auth_method'])+'" class="intable" onchange="changeRequestHTTPAuth(\''+html.escape(dom_id)+'\')">'
      for value in ('None', 'Basic', 'POST', 'Bearer token'):
        selected = ''
        if value.casefold() == http_parameters['auth_method'].casefold():
          selected = ' selected'
        self.html += '<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>'
      self.html += '</td><td></td></tr>'
      
      login_visible = (http_parameters['auth_method'].casefold() in ['basic', 'post', 'bearer token'])
      login_visible_style = 'table-row' if login_visible else 'none'
      self.html += '<tr id="'+html.escape(dom_id)+'_tr_auth_login" style="display: '+login_visible_style+';"><td>'+self.row_label('HTTP login', 'http_login')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_login" value="'+html.escape(http_parameters['auth_login'])+'" defaultValue="'+html.escape(http_parameters['auth_login'])+'" class="intable" type="text" data-clipboardcategory="client_id"></td>'
      self.html += '<td><span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span></td></tr>'
      secret_visible = (http_parameters['auth_method'].casefold() in ['basic', 'post'])
      secret_visible_style = 'table-row' if secret_visible else 'none'
      remember_secrets = Configuration.is_parameter_on(self.conf, '/preferences/clipboard/remember_secrets', False)
      clipboard = ' data-clipboardcategory="client_secret"' if remember_secrets else ''
      self.html += '<tr id="'+html.escape(dom_id)+'_tr_auth_secret" style="display: '+secret_visible_style+';"><td>'+self.row_label('Secret', 'http_secret')+'</td><td><input id="'+html.escape(dom_id)+'_d_auth_secret" defaultValue="" class="intable" type="password"'+clipboard+'></td>'
      self.html += '<td>'
      if clipboard != '':
        self.html += '<span class="cellimg"><img title="Clipboard" onclick="displayClipboard(this)" src="/images/clipboard.png"></span>'
      self.html += '</td><tr>'
      verify_cert_checked = " checked" if verify_certificates else ''
      verify_cert_default_checked = " defaultChecked" if verify_certificates else ''
      self.html += '<tr id="'+html.escape(dom_id)+'_tr_verify_cert"><td>'+self.row_label('Verify certificate', 'verify_certificate')+'</td><td><input id="'+html.escape(dom_id)+'_d_verify_cert" type="checkbox" '+verify_cert_checked+'></td><td></td></tr>'

    self.html += '</table>'
    
    self.html += '</form>'

    self.html += '<div id="'+html.escape(dom_id)+'_button_bar">'
    self.html += '<span class="middlebutton" onClick="reinitRequest(\''+html.escape(dom_id)+'\')">Reinit request</span>'
    if self.sender_url:
      self.html += '<span class="middlebutton" onClick="sendRequest(\''+html.escape(dom_id)+'\')">Send request</span>'
    self.html += '<span class="middlebutton" onClick="cancelRequest(\''+html.escape(dom_id)+'\', \''+html.escape(context)+'\')">Cancel</span>'
    self.html += '</div>'
    self.html += '<div id="'+html.escape(dom_id)+'_send_notification" style="display: none;">'
    self.html += '<h3>Sending request...</h3>'
    self.html += '</div>'
    
    self.javascript += """
      function f_"""+dom_id+"""_fetch_data(domId) {"""+data_generator+"""}

      function f_"""+dom_id+"""_update() {
        let method = document.getElementById('"""+dom_id+"""_method').value
        
        if (method == 'GET') {
          document.getElementById('"""+dom_id+"""_tr_request_data').style.display = 'none';
          f_"""+dom_id+"""_update_get()
        } else if (method == 'POST') {
          document.getElementById('"""+dom_id+"""_tr_request_data').style.display = 'table-row';
          f_"""+dom_id+"""_update_post()
        }
      }

      function f_"""+dom_id+"""_update_get() {
        let data = f_"""+dom_id+"""_fetch_data('"""+dom_id+"""');
        
        queryString = ""
        if (data) {
          for (const [key, value] of Object.entries(data)) {
            if (queryString != "") { queryString += "&" }
            queryString += encodeURI(key) + "=" + encodeURI(value);
          }
        }
        if (queryString != "") {
          let url = document.getElementById('"""+dom_id+"""_d_url').defaultValue;
          if (url.includes('?')) {
            url += '&' + queryString;
          } else {
            url += '?' + queryString;
          }
          document.getElementById('"""+dom_id+"""_d_url').value = url;
        }
      }

      function f_"""+dom_id+"""_update_post() {
        let data = f_"""+dom_id+"""_fetch_data('"""+dom_id+"""');
        if (data === null) { data = {} }
        if (document.getElementById('"""+dom_id+"""_d_auth_method').value == 'POST') {
          data['client_id'] = document.getElementById('"""+dom_id+"""_d_auth_login').value
          data['client_secret'] = '********'
        }
        
        document.getElementById('"""+dom_id+"""_d_data').value = JSON.stringify(data, null, 2);
      }

      f_"""+dom_id+"""_update();
    """
      
    self.javascript += "document.getElementById('"+dom_id+"_d_auth_login').addEventListener('keyup', f_"+dom_id+"_update);"
    for field in table['fields']:
      if field['type'] == 'edit_text':
        self.javascript += "document.getElementById('"+dom_id+"_d_"+field['name']+"').addEventListener('keyup', f_"+dom_id+"_update);"
      elif field['type'].startswith('edit_'):
        self.javascript += "document.getElementById('"+dom_id+"_d_"+field['name']+"').addEventListener('change', f_"+dom_id+"_update);"    
    
    
  def _append_requester(self):
    
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
        'hr_auth_login': "@[hr_auth_method] = 'basic' or @[hr_auth_method] = 'form' or @[hr_auth_method] = 'bearer_token'",
        'hr_auth_secret': "@[hr_auth_method] = 'basic' or @[hr_auth_method] = 'form'",
        'hr_auth_login_param': "@[hr_auth_method] = 'form' and (@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect')",
        'hr_auth_secret_param': "@[hr_auth_method] = 'form' and (@[hr_form_method] = 'post' or @[hr_form_method] = 'redirect')",
        'hr_verify_certificates': "True",
      }

      for field, visibility in self.visible_requester_fields.items():
        if not visibility:
          displayed_when_dict['hr_'+field] = "False"
      
      section_title = 'HTTP request' + (' for '+self.title if self.title else '')
      self.start_section('http_requester', title=section_title, level=2) \
        .raw_html('<label for="{input_id}">Modify request</label><input type="checkbox" id={input_id} name="modify_request" />'.format(input_id=self.form_uuid+"_modify_request")) \
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
          values={'none': 'None', 'basic': 'Basic', 'form': 'Form', 'bearer_token': 'Bearer token'},
          default = 'None'
          ) \
        .text('hr_auth_login', label='HTTP login', clipboard_category='client_id', displayed_when=displayed_when_dict['hr_auth_login']) \
        .text('hr_auth_login_param', label='Login parameter name', displayed_when=displayed_when_dict['hr_auth_login_param']) \
        .password('hr_auth_secret', label='HTTP secret', clipboard_category='client_secret', displayed_when=displayed_when_dict['hr_auth_secret']) \
        .text('hr_auth_secret_param', label='Secret parameter name', displayed_when=displayed_when_dict['hr_auth_secret_param']) \
        .check_box('hr_verify_certificates', label='Verify certificates', displayed_when=displayed_when_dict['hr_verify_certificates']) \
      .end_section()

    
    
      