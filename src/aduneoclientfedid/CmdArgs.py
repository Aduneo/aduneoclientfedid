# -*- coding: utf-8 -*-
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

import time
import sys

class CmdArgs:
  """
  Analyse les arguments de la ligne de commande et les restitue en fonction des besoins du script

  Les arguments doivent être de la forme :
  -arg1 valeur -arg2

  Les besoins du script sont décrits dans un table avec
  - clé : nom de l'argument (sans le tiret) - attention la casse est importante
  - valeur : type(valeurs acceptées)[valeur par défaut]

  Les types suivants sont autorisés
  - string
  - strings séparées par des virgules, restituées en tableau (tableau vide si l'argument n'est pas donné)
  - int
  - option(val1, valn)
  - options(val1, valn) séparées par des virgules, restituées en tableau (tableau vide si l'argument n'est pas donné)
  - switch (valeur booléenne avec valeur false par défaut. Si l'argument est donné, la valeur est true)
  - date au format aaaammjjhhmmss

  Le séparateur des valeurs multiples est la virgule par défaut. Il est sinon donné dans le paramètre value_separator.

  Si on donne l'espace comme séparateur, on peut utiliser les caractères génériques (*) pour récupérer des noms de fichiers.
  (en shell, en mettant une étoile, le Python récupére des noms de fichiers, mais il n'a pas accès à l'étoile à moins de la mettre entre guillemets)

  Exemple :
  {'mode': 'option(differentiel,complet)[differentiel]', 'start': 'date', 'end': 'date', 'dev': 'switch'}

  Note: pour l'instant on ne peut pas indiquer d'argument obligatoire

  """
  
  def __init__(self, accepted_params:dict, value_separator:str = ','):
  
    self.accepted_params = accepted_params
    self.value_separator = value_separator
    self.parsed_args = {}
    
    self._parse()
    
  
  def _parse(self):
  
    self.parsed_args = {}
    args_format = {}
    
    # peuplement d'après les valeurs par défaut
    for arg in self.accepted_params.keys():
    
      accepted_values = None
      default_value = None
      argument_type = self.accepted_params[arg]
      parenthesis_o_pos = self.accepted_params[arg].find('(')
      parenthesis_c_pos = -1
      if parenthesis_o_pos > 0:
        parenthesis_c_pos = self.accepted_params[arg].find(')')
        if parenthesis_c_pos == -1:
          raise Exception("argument definition incorrect for argument %s: no closing parenthesis" % arg)
        accepted_values = self.accepted_params[arg][parenthesis_o_pos+1:parenthesis_c_pos]
        argument_type = self.accepted_params[arg][:parenthesis_o_pos]
      bracket_o_pos = self.accepted_params[arg].find('[')
      if bracket_o_pos > 0:
        bracket_c_pos = self.accepted_params[arg].find(']')
        if bracket_c_pos == -1:
          raise Exception("argument definition incorrect for argument %s: no closing bracket" % arg)
        default_value = self.accepted_params[arg][bracket_o_pos+1:bracket_c_pos]
        if parenthesis_c_pos == -1:
          argument_type = self.accepted_params[arg][:bracket_o_pos]
        
      if argument_type not in ('string', 'strings', 'int', 'option', 'options', 'switch', 'date'):
        raise Exception("argument definition incorrect for argument %s: type %s unknown" % (arg, argument_type))

      if argument_type == 'switch':
        if default_value:
          if default_value.casefold() == 'false':
            self.parsed_args[arg] = False
          elif default_value.casefold() == 'true':
            self.parsed_args[arg] = True
          else:
            raise Exception('default value for argument "'+arg+'" unknown. "'+arg+'" is a switch, therefore expected values are "false" and "true"')
        else:
          self.parsed_args[arg] = False
      elif argument_type == 'strings' or argument_type == 'options':
        self.parsed_args[arg] = []
        if default_value:
          for value in default_value.split(self.value_separator):
            self.parsed_args[arg].append(value.strip())
      elif argument_type == 'int':
        if default_value:
          self.parsed_args[arg] = int(default_value)
      elif default_value is not None:
        self.parsed_args[arg] = default_value

      args_format[arg] = {'type': argument_type, 'accepted_values': accepted_values}

    # peuplement complémentaire par la ligne de commandes
    iarg = 1
    while iarg < len(sys.argv):
      arg = sys.argv[iarg]
      if arg[0] != '-':
        raise Exception("syntax error, an argument should start with a dash, %s found" % arg[0])
      arg = arg[1:]
      if arg not in self.accepted_params.keys():
        raise Exception("unknown argument %s" % arg)

      argument_type = args_format[arg]['type']
      accepted_values = args_format[arg]['accepted_values']
      
      value = None
      if argument_type in ('strings', 'options'):
        # valeurs multiples
        iarg += 1
        if iarg == len(sys.argv):
          raise Exception("argument %s without a value" % arg)
        
        read_value = True
        value = sys.argv[iarg] 
        if self.value_separator == ' ':
          while read_value:
            if (iarg+1) == len(sys.argv):
              read_value = False
            else:
              if sys.argv[iarg+1][0] == '-':
                read_value = False
              else:
                iarg += 1
                value += ' '+sys.argv[iarg]
        else:
          value = value.strip()
          while read_value:
            read_value = False
            if value.endswith(self.value_separator):
              read_value = True
            else:
              if (iarg+1) < len(sys.argv):
                if sys.argv[iarg+1].strip().startswith(self.value_separator):
                  read_value = True
              
            if read_value:
              iarg += 1
              if iarg == len(sys.argv):
                raise Exception('value missing for argument '+arg+': '+value+' given')
              value += sys.argv[iarg].strip()
          
      elif argument_type in ('string', 'strings', 'int', 'option', 'options', 'date'):
        # valeur simple
        iarg += 1
        if iarg == len(sys.argv):
          raise Exception("argument %s without a value" % arg)
        value = sys.argv[iarg]
      elif argument_type != 'switch':
        raise Exception("argument definition incorrect for argument %s: type %s unknown" % (arg, argument_type))
        
      if argument_type == 'string':
        self.parsed_args[arg] = value
      elif argument_type == 'int':
        self.parsed_args[arg] = int(value)
      elif argument_type == 'strings':
        self.parsed_args[arg] = []
        for item in value.split(self.value_separator):
          self.parsed_args[arg].append(item.strip())
      elif argument_type == 'option':
        valid_values = accepted_values.replace(' ', '').split(',')
        if value not in valid_values:
          raise Exception("value %s not valid for argument %s" % (value, arg))
        self.parsed_args[arg] = value
      elif argument_type == 'options':
        self.parsed_args[arg] = []
        valid_values = accepted_values.replace(' ', '').split(',')
        for item in value.split(self.value_separator):
          item = item.strip()
          if item not in valid_values:
            raise Exception("value %s not valid for argument %s" % (item, arg))
          self.parsed_args[arg].append(item)
      elif argument_type == 'date':
        value = (value+'000000')[:14]
        self.parsed_args[arg] = time.strptime(value, '%Y%m%d%H%M%S')
      elif argument_type == 'switch':
        self.parsed_args[arg] = True
      
      iarg += 1
    
