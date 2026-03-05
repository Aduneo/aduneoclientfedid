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
import logging

from ..BaseServer import AduneoError


class BruteForce:
  """ Protection de l'authentification des attaques de type force brute
  """
  
  """
  {
    "<login>": {
      "status": {
        "suspended": bool,
        "reactivation_date": datetime
      },
      "cookies": [
        {
          "value": "<cookie value>",
          "date": datetime
        }
      ],
      events: [
        {
          "status": "success|failure",
          "date": datetime,
          "IP": "<IP address>"
        }
      ]
    }
  }
  """
  contexts = {}
  
  try_delay = datetime.timedelta(seconds=1)        # délai minimal entre deux tentatives d'authentification
  
  
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
    
    allowed = True
    
    login_context = BruteForce.contexts.get(login)
    if (login_context):

      if (allowed):
        # première condition : la fréquence de demandes d'authentification
        if datetime.datetime.now() - login_context['events'][-1]['date'] < BruteForce.try_delay:
          allowed = False
      
      if (allowed):
        # seconde condition : que le compte de soit pas suspendu
        if login_context['status']['suspended']:
          pass
      


    return allowed


  def failed_auth(self, login:str, http_handler):
    """ Retour d'authentification erronée, pour prise en compte
    
    On enregistre la tentative pour exploitation
    
    Args:
      login: identifiant en question
      http_handler: BaseHandler avec le contexte d'authentification
      
    Versions:
      21/02/2026 (mpham) version initiale
    """
    login = login.lower()
    login_context = BruteForce.contexts.get(login)
    if not login_context:
      login_context = {
        "status": {
          "suspended": False,
          "date": datetime
          },
        "cookies": [],
        "events": []
        }
      BruteForce.contexts[login] = login_context
    login_context['events'].append({
      "status": "failure",
      "date": datetime.datetime.now(),
      "IP": http_handler.ip_address
      })


  def successful_auth(self, login:str, http_handler):
    """ Retour d'authentification réussie, pour prise en compte de la protection
    
    Args:
      login: identifiant en question
      http_handler: BaseHandler avec le contexte d'authentification
      
    Versions:
      21/02/2026 (mpham) version initiale
    """
    login = login.lower()
    login_context = BruteForce.contexts.get(login)
    if not login_context:
      login_context = {
        "status": {
          "suspended": False,
          "date": datetime
          },
        "cookies": [],
        "events": []
        }
      BruteForce.contexts[login] = login_context
    login_context['events'].append({
      "status": "success",
      "date": datetime.datetime.now(),
      "IP": http_handler.ip_address
      })
    #http_handler.hreq.send_header('Set-Cookie', 'azt='+'test'+'; HttpOnly')

