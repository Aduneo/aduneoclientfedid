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

import json
import logging
import os

class Explanation:
  """ Fournit des explications sur les erreurs rencontrées
  
  Versions
    02/03/2023 (mpham) : version initiale
  """
  
  explanation_json = None
  reload = True
  
  def get(code:str) -> str:
    """ Retourne l'explication correspondant au code donné
    
    Pour l'instant la langue n'est pas gérée (anglais par défaut)
    
    Args:
      code: identifiant unique de l'explication
      
    Returns:
      l'explication (en HTML) ou un message d'erreur compréhensible
    
    Versions
      02/03/2023 (mpham) : version initiale
    """
    
    explanation = 'No explanation found for code: '+code
    
    language = 'en'
    
    explanation_json = Explanation._get_json()
    item = explanation_json.get(code)
    if item:
      explanation = item.get('content_'+language, explanation)
    
    return explanation
    
  
  def _get_json() -> dict:
    """ Retourne le contenu du fichier JSON data/explanation.json
    
    Format du fichier :
    {
      "<code>": {
        "content_<langue>": "<HTML>"
      }
    
    Par défaut ne le lit qu'une seule fois à la première invocation de la méthode.
    
    Sauf si la variable Explanation.reload est à True
    
    Returns:
      Contenu du fichier JSON data/explanation.json sous forme de dict
    
    """
  
    if Explanation.explanation_json is None or Explanation.reload:
    
      data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
      print(data_dir)
      explanation_filepath = os.path.join(data_dir, 'explanation.json')

      with open(explanation_filepath, encoding='utf8') as json_file:
        Explanation.explanation_json = json.load(json_file)
    
    return Explanation.explanation_json
  
  
