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

from .BaseServer import DesignError


class Proposition:
  """ Représente une proposition mathématique du type variable = valeur
    avec les opérateurs and, or, et les parenthèses
    
    pour :
      - évaluation dynamique
      - transcription en Javascript
    
    dans la proposition, les variables sont préfixées par une arobase et entourées de crochets, par exemple @[var]
    
    Une proposition élémentaire peut être
      - True
      - False
      - opérande = opérande (opérande étant une variable ou une constante)
      - variable (pour les variables booléennes)
    
    lors de l'évaluation, les valeurs des variables sont transmises dans un dict :
      - clé : nom de la variable (sans l'arobase ni les crochets)
      - valeur

    Opérateurs supportés :
      =
      
    Ne fait pas d'opérations mathématiques
    
  Versions:
    29/12/2023 (mpham) version initiale
  """

  def __init__(self, proposition):
    self.proposition = proposition
    self.variables = []
    

  def eval(self, variables:dict) -> bool:
    self.variables = []
    return self._eval_proposition(self.proposition, variables)
    
  
  def transpose_javascript(self, transpose_function, variable_types={}) -> str:
    """ Retourne le code Javascript d'une proposition mathématique
    
    Args:
      transpose_function: fonction qui prend un nom de variable et le convertit en code Javascript en retournant la valeur
      variable_types: meta informations sur les variables pour aider à la construction du code Javascript de conversion
    
    Versions:
      29/12/2023 (mpham) version initiale
      02/01/2025 (mpham) on a besoin des types des champs pour les checkbox
    """
       
    js = self.proposition
    js = js.replace('=', '==').replace(' and ', ' && ').replace(' or ', ' || ')

    transposed = ''
    current_pos = 0
    arobase_pos = js.find('@[')
    while arobase_pos != -1:
      transposed += js[current_pos:arobase_pos]
      variable_end_pos = self._find_variable_end(js, arobase_pos)
      variable = js[arobase_pos+2:variable_end_pos]
      transposed += transpose_function(variable, variable_types)
      current_pos = variable_end_pos+1
      arobase_pos = js.find('@[', current_pos)
    transposed += js[current_pos:]
    
    return transposed
  
  
  def _find_variable_end(self, js:str, pos:int) -> int:
    
    end_pos = js.find(']', pos)
    if end_pos == -1:
      raise DesignError("missing matching closing bracket at position {position} in {string}".format(position=pos, string=js))
    
    """
    loop = pos < len(js)
    while loop:
      if 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_012346789'.find(js[pos]) == -1:
        loop = False
      else:
        pos += 1
        loop = pos < len(js)
    
    return pos
    """
    return end_pos
  
  
  def _eval_proposition(self, proposition:str, variables:dict) -> bool:
    """
    Versions:
      29/12/2023 (mpham) version initiale
      02/01/2025 (mpham) variables booléennes (pour les checkbox)
    """

    # On commence par isoler les expressions entre parenthèses
    flat_expression = ''
    current_pos = 0
    open_bracket_pos = proposition.find('(')
    while open_bracket_pos > 0:
      flat_expression += proposition[current_pos:open_bracket_pos]
      closed_bracket_pos = self._find_closed_bracket(proposition, open_bracket_pos)
      sub_expression = proposition[open_bracket_pos+1:closed_bracket_pos]
      #print('()', sub_expression)
      flat_expression += ' '+str(self._eval_proposition(sub_expression, variables))+' '
      current_pos = closed_bracket_pos+1
      open_bracket_pos = proposition.find('(', current_pos)
    flat_expression += proposition[current_pos:]
    #print(flat_expression)
    
    # On commence par identifier les sous-expressions en or
    if flat_expression.find(' or ') >= 0:
      result = False
      for sub_expression in flat_expression.split(' or '):
        #print('or ->', sub_expression)
        if self._eval_proposition(sub_expression, variables):
          result = True
          
    elif flat_expression.find(' and ') >= 0:
      result = True
      for sub_expression in flat_expression.split(' and '):
        #print('and ->', sub_expression)
        if not self._eval_proposition(sub_expression, variables):
          result = False
    else:
      sub_expression = flat_expression.strip()
      if sub_expression == 'True':
        result = True
      elif sub_expression == 'False':
        result = False
      else:
        equals_pos = sub_expression.find('=')
        if equals_pos == -1:
          # Variable booléenne
          result = self._compute(sub_expression, variables)
        else:
          left_term = sub_expression[0:equals_pos].strip()
          right_term = sub_expression[equals_pos+1:].strip()
          result = (self._compute(left_term, variables) == self._compute(right_term, variables))
    
    return result
    
    
  def _find_closed_bracket(self, string:str, open_bracket_pos:int) -> int:
    
    level = 1
    
    current_pos = open_bracket_pos+1
    while level > 0:
      open_bracket_pos = string.find('(', current_pos)
      closed_bracket_pos = string.find(')', current_pos)
      if closed_bracket_pos == -1:
        raise DesignError("Closing bracket not found in {string}".format(string=string))
      if open_bracket_pos == -1:
        level -= 1
        current_pos = closed_bracket_pos+1
      elif open_bracket_pos < closed_bracket_pos:
        level += 1
        current_pos = open_bracket_pos+1
      else:
        level -= 1
        current_pos = closed_bracket_pos+1
        
    return current_pos-1
    
    
  def _compute(self, expression:str, variables:dict):
    
    result = None
    expression = expression.strip()
    
    if expression.startswith('@['):
      if not expression.endswith(']'):
        raise DesignError("missing matching closing bracket in {string}".format(string=expression))
      variable = expression[2:-1]
      result = variables[variable]
      if variable not in self.variables:
        self.variables.append(variable)
    elif expression.startswith('"'):
      if not expression.endswith('"'):
        raise DesignError("missing closing quote in {expression}".format(expression=expression))
      result = expression[1:-1]
    elif expression.startswith("'"):
      if not expression.endswith("'"):
        raise DesignError("missing closing quote in {expression}".format(expression=expression))
      result = expression[1:-1]
    else:
      result = int(expression)
    
    #print('_compute', expression, result)
    
    return result  