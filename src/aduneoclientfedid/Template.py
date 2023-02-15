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

import html

class Template:
  
  """
    Mécanisme de template simplifié
    
    Accepte les balises suivantes :
      - {{ expression }} : insertion d'expressions, pouvant contenir des variables passées en paramètres
      - {% statement %} : insertion de commandes Python, pouvant contenir des variables passées en paramètres
        Seules les structures if, for et while sont autorisées
      
    Attention, il est préférable de mettre une seule commande par {% %}, surtout si on utilise les commandes if, for et while
    
    On termine une commande if, for ou while par {% endif %}, {% endfor %} et {% endwhile %} respectivement
    
    Les paramètres sont passés en argument de la commande apply_template, avec la forme <parameter>=<value>
    
    Exemple de template :
      items = [{"nom": "Clavier", "prix": "20€"}, {"nom": "Souris", "prix": "10€"}]
      print(Template.apply_template("Bonjour {{ nom }}. {% for i in range(1,5) %} Hello {{ i*m }} {% endfor %}{% for item in items %} Nom {{ item['nom'] }} Prix {{ item['prix'] }} {% endfor %} {% if nom == 'Jean' %} Mais c'est Jean ! {% elif nom == 'Pierre' %} Mais c'est Pierre ! {% else %} Ce n'est ni Jean ni Pierre {% endif %}", 
        nom='Pierre', m=6, items=items))

  """
  
  
  def apply_template(text, **values):

    code = '__mruqx = ""\n'
      
    for key in values.keys():
      code += key + '=' + 'values.get("'+key+'")\n'
      
    c_bracket_pos = -2
    o_expr_pos = text.find('{{')
    o_stat_pos = text.find('{%')
    indent = 0
    while (o_expr_pos > -1) or (o_stat_pos > -1):

      # on détermine si la première accolade est expr ou stat
      o_bracket_pos = o_stat_pos
      if o_expr_pos > -1:
        if o_stat_pos > -1:
          o_bracket_pos = min(o_expr_pos, o_stat_pos)
        else:
          o_bracket_pos = o_expr_pos

      literal_code = ''
      if o_bracket_pos - c_bracket_pos-2 > 0:
        literal_code = text[c_bracket_pos+2:o_bracket_pos-1]
        if text[o_bracket_pos-1] == '"':
          literal_code += '\\'
        literal_code += text[o_bracket_pos-1]
      code += ' '*indent+'__mruqx+="""'+literal_code+'"""\n'
    
      # première accolade est de type expr
      if text.startswith('{{', o_bracket_pos):
    
        c_bracket_pos = text.find('}}', o_bracket_pos)
        if c_bracket_pos == -1:
          raise AduneoError('no closing bracket }} position '+str(o_bracket_pos)+' in '+text)
        expression = text[o_bracket_pos+2:c_bracket_pos].strip()
        code += ' '*indent+'__mruqx += str('+expression+')\n'

      # première accolade est de type statement
      else:
      
        c_bracket_pos = text.find('%}', o_bracket_pos)
        if c_bracket_pos == -1:
          raise AduneoError('no closing bracket %} position '+str(o_bracket_pos)+' in '+text)
        statement = text[o_bracket_pos+2:c_bracket_pos].strip()
        if statement in ['endif', 'endfor', 'endwhile']:
          indent -= 1
          if indent<0:
            raise AduneoError('unexpected {% '+statement+' %} position '+str(o_bracket_pos)+' in '+text)
        else:
          new_indent = indent
          cmd = statement
          space_pos = statement.find(' ')
          if space_pos>-1:
            cmd = statement[:space_pos]
          if cmd in ['if', 'for', 'while']:
            statement += ':'
            new_indent += 1
          elif cmd in ['else', 'elif']:
            statement += ':'
            indent -= 1
            if indent<0:
              raise AduneoError('unexpected {% '+cmd+' %} position '+str(o_bracket_pos)+' in '+text)

          code += ' '*indent+statement+'\n'
          indent = new_indent
      
      o_expr_pos = text.find('{{', c_bracket_pos)
      o_stat_pos = text.find('{%', c_bracket_pos)
    
    if c_bracket_pos+2 < len(text):
      literal_code = text[c_bracket_pos+2:-1]
      if text[-1] == '"':
        literal_code += '\\'
      literal_code += text[-1]
      code += ' '*indent+'__mruqx+="""'+literal_code+'"""\n'

    _locals = locals()
    #print(code)
    exec(code, globals(), _locals)
    return _locals['__mruqx']
