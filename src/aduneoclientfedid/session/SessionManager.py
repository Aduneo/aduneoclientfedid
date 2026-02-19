"""
Copyright 2026 Aduneo

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

from .EmbeddedSessionManager import EmbeddedSessionManager

  
class SessionManager:
  """ Factory des gestionnaires de session
  
  On gère un singleton, que l'on appelle par
  
  session_manager = SessionManager(conf)
  
  Configuration :
    {
      "server": {
        "sessions": {
          "manager": "<nom du gestionnaire>"
        }
      }
    }
  
  """
  
  _instance = None
  session_timeout = 20*60 # en secondes


  def __new__(cls, conf:dict):
    """ Singleton
    
    voir https://python-patterns.guide/gang-of-four/singleton/
    
    Versions:
      17/02/2026 (mpham) version initiale
    """
    
    if cls._instance is None:
      
      # on détermine le type de session
      session_type = 'EmbeddedSessionManager'

      try:
        session_type = conf['/server/sessions/manager']
      except:
        pass
      
      if session_type == 'EmbeddedSessionManager':
        cls._instance = EmbeddedSessionManager(conf)
      else:
        raise Exception(f"session manager {session_type} inconnu")
      
    return cls._instance  
    
  
  def is_session_valid(self, session_id:str) -> bool:
    """ indique si un session est toujours valide
    
    Args:
      session_id: identifiant unique de la session
      
    Returns:
      True si la session est valide
      
    Versions:
      17/02/2026 (mpham) version initiale
    """
    return False


  def create_session(self) -> str:
    """ crée une nouvelle session
    
    Args:
      session_id: identifiant unique de la session
      
    Returns:
      True si la session est valide
      
    Versions:
      17/02/2026 (mpham) version initiale
    """
    return None


  def set_session_value(self, session_id:str, key:str, value):
    """ Met une variable en session

    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
      value: valeur de la variable

    Versions:
      18/02/2026 (mpham) version initiale
    """
    
    
  def get_session_value(self, session_id:str, key:str):
    """ Récupère une variable de la session
    
    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
      
    Returns:
      valeur de la variable, None si elle n'existe pas
    
    Versions:
      18/02/2026 (mpham) version initiale
    """
    
    
  def del_session_value(self, session_id:str, key:str):
    """ Supprime une variable de la session

    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
    
    Versions:
      18/02/2026 (mpham) version initiale
    """

    
  def expire_sessions(self):
    """ Supprime les sessions expirées si la gestion 
    
    Versions:
      18/02/2026 (mpham) version initiale
    """
