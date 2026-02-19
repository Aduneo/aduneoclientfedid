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
import datetime
import uuid

 
class EmbeddedSessionManager():
  """ Gestionnaires de session par une variable statique
  
  Attention, ne fonctionne pas en multiprocessor, car on a alors autant de valeurs de statiques que de processeurs

  Configuration :
    {
      "server": {
        "sessions": {
          "manager": "<nom du gestionnaire>",
          "session_time_out": 1200
        }
      }
    }
  """
  
  """
    {
      <identifiant de session>: {
        'id': <identifiant de session>,
        'expires': 'datetime d'expiration',
        'date': {}
      }
    }
  """
  sessions = {}
  
  
  def __init__(self, conf:dict):
    """ Constructeur
    
    Versions:
      17/02/2026 - 19/02/2026 (mpham) version initiale
    """
    
    try:
      session_timeout = int(conf['/server/sessions/manager/session_time_out'])
    except:
      from .SessionManager import SessionManager
      self.session_timeout = SessionManager.session_timeout
    
  
  def is_session_valid(self, session_id:str) -> bool:
    """ indique si un session est toujours valide
    
    Args:
      session_id: identifiant unique de la session
      
    Returns:
      True si la session est valide
      
    Versions:
      17/02/2026 (mpham) version initiale
    """
    
    valid = False
    
    session = EmbeddedSessionManager.sessions.get(session_id)
    if (session):
      if session['expires'] > datetime.datetime.now():
        valid = True
        self.update_session_expiration(session)
      else:
        del EmbeddedSessionManager.sessions[session_id]
        
    return valid


  def create_session(self) -> str:
    """ crée une nouvelle session
    
    Args:
      session_id: identifiant unique de la session
      
    Returns:
      True si la session est valide
      
    Versions:
      17/02/2026 (mpham) version initiale
    """
    session_id = str(uuid.uuid4())
    session = {
      'id': session_id,
      'data': {}
    }
    self.update_session_expiration(session)
    EmbeddedSessionManager.sessions[session_id] = session
    
    return session_id


  def set_session_value(self, session_id:str, key:str, value):
    """ Met une variable en session

    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
      value: valeur de la variable
    
    18/02/2026 (mpham) version initiale
    """
    
    session = EmbeddedSessionManager.sessions.get(session_id)
    if (session):
      session['data'][key] = value
      self.update_session_expiration(session)


  def get_session_value(self, session_id:str, key:str):
    """ Récupère une variable de la session
    
    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
      
    Returns:
      valeur de la variable, None si elle n'existe pas
    
    18/02/2026 (mpham) version initiale
    """
    
    value = None
    
    session = EmbeddedSessionManager.sessions.get(session_id)
    if (session):
      value = session['data'].get(key)
      self.update_session_expiration(session)
      
    return value
    
    
  def del_session_value(self, session_id:str, key:str):
    """ Supprime une variable de la session

    Args:
      session_id: identifiant d'une session valide
      key: nom de la variable
    
    Versions:
      18/02/2026 (mpham) version initiale
    """
    session = EmbeddedSessionManager.sessions.get(session_id)
    if (session):
      session['data'].pop(key, None)
      self.update_session_expiration(session)
    
    
  def expire_sessions(self):
    """ Supprime les sessions expirées
    
    Versions:
      18/02/2026 (mpham) version initiale
    """

    now = datetime.datetime.now()
    
    session_id_to_delete = []
    for session_id, session in EmbeddedSessionManager.sessions.items():
      if session['expires'] < now:
        session_id_to_delete.append(session_id)
        
    for session_id in session_id_to_delete:
      del EmbeddedSessionManager.sessions[session_id]
        
    
  def update_session_expiration(self, session:dict):
    """ repousse l'expiration d'une session
    
    Args:
      session: wrapper de session
      
    Versions:
      17/02/2026 (mpham) version initiale
    """
    session['expires'] = datetime.datetime.now() + datetime.timedelta(seconds=self.session_timeout)
