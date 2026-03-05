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
import logging

from .BruteForce import BruteForce
from ..BaseServer import AduneoError


class AuthProtection:
  """ Protection de l'authentification

    Pour l'instant force brute
  """
  
  instance = None

  def __new__(cls):
    """ Singleton
    
    voir https://python-patterns.guide/gang-of-four/singleton/
    
    Versions:
      21/02/2026 (mpham) version initiale
    """
    
    if cls.instance is None:
      cls.instance = super(AuthProtection, cls).__new__(cls)
      # Put any initialization here.
      cls.brute_force = BruteForce()
    return cls.instance  
    
  
  def is_auth_allowed(self, login:str, http_handler) -> bool:
    """ Indique, en fonction du contexte, si on autorise l'authentication (après la saisie du login)
    
    Args:
      login: identifiant en question
      http_handler: BaseHandler avec le contexte d'authentification
      
    Returns:
      true si on peut continuer et vérifier le secret
      
    Versions:
      21/02/2026 (mpham) version initiale
    """
    return AuthProtection.brute_force.is_auth_allowed(login, http_handler)


  def failed_auth(self, login:str, http_handler):
    """ Retour d'authentification erronée, pour prise en compte de la protection
    
    Args:
      login: identifiant en question
      http_handler: BaseHandler avec le contexte d'authentification
      
    Versions:
      21/02/2026 (mpham) version initiale
    """
    AuthProtection.brute_force.failed_auth(login, http_handler)


  def successful_auth(self, login:str, http_handler):
    """ Retour d'authentification réussie, pour prise en compte de la protection
    
    Args:
      login: identifiant en question
      http_handler: BaseHandler avec le contexte d'authentification
      
    Versions:
      21/02/2026 (mpham) version initiale
    """
    AuthProtection.brute_force.successful_auth(login, http_handler)
