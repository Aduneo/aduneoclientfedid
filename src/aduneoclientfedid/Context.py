"""
Copyright 2024 Aduneo

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
import copy
import uuid

class Context(dict):
  """ Représente le contexte d'une session d'authentification
    
    Correspond à un IdP et une application de cet IdP
    Il est initialisé lors de la première requête d'authentification (OIDC, OAuth ou SAML)
    Il est mis à jour lors que chaque cinématique ultérieur (userinfo, introspection, token exchange)
      Mais on conserve les valeurs initiales de la première requête pour pouvoir la rejouer
      
    Un contexte est identifié par un identifiant unique qui permet de le retrouver côté serveur (dans la session)
      Cet identifiant est passé lors de chaque échange avec le navigateur
      => context['context_id']
    
    En revanche, le contexte n'est pas toujours récupéré directement.
      Ce n'est par exemple pas le cas quand son identifiant n'est pas transmis au navigateur, le cas d'usage étant 
      le retour d'authentification : l'IdP retourne le state, qu'on n'initialise pas au context_id pour assurer son 
      unicité. On conserve donc en session une correspondance state -> context_id pour récupérer l'objet de contexte.
    
    La structure de Context est de type JSON : organisation non contrainte de dict et list

    Le contexte est découpé en plusieurs parties :
    - identfication de la dernière authentification (identifiant de l'IdP et du client)
    - paramètres de l'IdP, qu'il est possible de modifier et que l'on conserve pour persistance des modifications
    - paramètres des différents clients ayant fait l'objet d'une authentification, qu'il est possible de modifier et que l'on conserve pour persistance des modifications
    - paramètres de la dernière introspection
    - jetons récupérés lors des différentes cinématiques
    
    (on ne conserve rien concernant les API (de la configuration) car on ne peut actuellement rien modifier dans le cours des cinématiques).
      En revanche, on conserve les valeurs saisies manuellement de la dernière introspection (ou plus précisément de la dernière introspection
      lancée manuellement)

    Structure type du contexte :
    
    context: {
      'idp_id': '<identifiant de l'IdP concerné par la cinématique en cours>',
      'app_id': '<identifiant du client ayant réalisé la dernière authentification>',
      'flow_type': '<dernière cinématique : OIDC, OAuth2, SAML ou CAS>',
      'idp_params': { paramètres liés à l'IdP },
      'app_params': {
        '<app id>': { paramètres liés à la requête et plus largement au client },
      },
      'api_params': { paramètres liés à la dernière introspection },
      'id_tokens': {
        '<timestamp de l'obtention du jeton>': {
          'name': '<nom du jeton>';
          'type': 'id_token', 
          'app_id': '<app id du client ayant obtenu les jetons>',
          'id_token': '<jeton d'identité>',
          'access_token': '<jeton d'accès associé, s'il est retourné>',
          'refresh_token': '<jeton de rafraîchissement du jeton d'accès associé, s'il est retourné>',
        }
      },
      'access_tokens': {
        '<timestamp de l'obtention du jeton>': {
          'name': '<nom du jeton>';
          'type': 'access_token', 
          'app_id': '<app id du client ayant obtenu les jetons>',
          'access_token': '<jeton d'accès associé, s'il est retourné>',
          'refresh_token': '<jeton de rafraîchissement du jeton d'accès associé, s'il est retourné>',
        }
      },
      'saml_assertions': {
        '<timestamp de l'obtention de l'assertion>': {
          'name': '<nom de l'assertion>';
          'type': 'saml_assertion', 
          'app_id': '<app id du client ayant obtenu les jetons>',
          'saml_assertion': '<assertion en XML>',
          'name_id': '<name_id retourné par l'IdP, utilisé pour le logout>',
          'name_id_format': '<format du name_id, retourné par l'IdP, utilisé pour le logout>',
          'session_index': '<index de session retourné par l'IdP, utilisé pour le logout>'
        }
      }
    }

    Données liées à l'IdP : endpoints, issuer, clés de signature
    Données liées à un client : redirct_uri, client, secret, scopes, etc.
    Données liées à la dernière authentification : client, secret, méthode d'authentification
    
    access_tokens ne contient que les jetons obtenus par OAuth 2
    
    Si on souhaite avoir tous les jetons d'accès, y compris ceux récupérés en OIDC, il suffit d'appeler
      get_all_access_tokens
    
    
  Versions:
    08/08/2024 (mpham) version initiale
    05/09/2024 (mpham) refonte du contexte et intégration des paramètres de la dernière introspection
    28/11/2024 (mpham) on ajoute l'app ayant obtenu le jeton d'accès pour pouvoir le rafraîchir
    28/01/2025 (mpham) tickets CAS (attention, ils sont inutilisables)
  """

  def __init__(self):
    self['context_id'] = str(uuid.uuid4())
    self['idp_params'] = {}
    self['app_params'] = {}
    self['api_params'] = {}
    self['id_tokens'] = {}
    self['access_tokens'] = {}
    self['saml_assertions'] = {}
    self['cas_tickets'] = {}


  def get_all_access_tokens(self) -> dict:
    """ Retourne l'ensemble des jetons d'accès
          - ceux obtenus par OAuth 2
          - ainsi que ceux récupérés avec un jeton d'identité en OIDC

    Returns:
      dict de la forme
        {
          '<timestamp de l'obtention du jeton>': {
            'name': '<nom du jeton';
            'type': 'access_token', 
            'app_id': '<app id du client ayant obtenu les jetons>',
            'access_token': '<jeton d'accès associé, s'il est retourné>',
            'refresh_token': '<jeton de rafraîchissement du jeton d'accès associé, s'il est retourné>',
          },
          '<timestamp de l'obtention du jeton>': {
          ...
          }
        }
      
          
    Versions:
      28/08/2024 (mpham) version initiale
      05/09/2024 (mpham) on retourne aussi le jeton de rafraîchissement
      30/12/2024 (mpham) on retourne aussi app_id
    """

    access_tokens = copy.deepcopy(self['access_tokens'])
    for token_wrapper_key in self['id_tokens'].keys():
      token_wrapper = self['id_tokens'][token_wrapper_key]
      access_tokens[token_wrapper_key] = {'name': token_wrapper['name'], 'access_token': token_wrapper['access_token'], 'app_id': token_wrapper['app_id']}
      if 'refresh_token' in token_wrapper:
        access_tokens[token_wrapper_key]['refresh_token'] = token_wrapper['refresh_token']

    return access_tokens
    

  def get_all_tokens(self) -> dict:
    """ Retourne l'ensemble des jetons et assertions du contexte : 
          - identité (OIDC), accès (OAuth2, OIDC), rafraîchissement (OAuth2, OIDC), SAML
          - obtenus par Token Exchange

    Returns:
      list de la forme
        [
          {
            'name': '<nom du jeton';
            'type': '<id_token|access_token|refresh_token|saml_assertion>', 
            'app_id': '<app id du client ayant obtenu les jetons>',
            'token': '<jeton>',
            'timestamp': <timestamp de l'obtention du jeton>,
          },
          {
          ...
          }
        ]
      
          
    Versions:
      25/02/2025 (mpham) version initiale
    """

    all_token_wrappers = []

    # OIDC tokens
    for token_wrapper_key, token_wrapper in self.get('id_tokens', {}).items():
      all_token_wrappers.append({
        'name': 'ID: '+token_wrapper['name'], 
        'type': 'id_token',
        'token': token_wrapper['id_token'],
        'app_id': token_wrapper['app_id'],
        'timestamp': token_wrapper_key,
        })
      if token_wrapper.get('access_token'):
        all_token_wrappers.append({
          'name': 'AT: '+token_wrapper['name'], 
          'type': 'access_token',
          'token': token_wrapper['access_token'],
          'app_id': token_wrapper['app_id'],
          'timestamp': token_wrapper_key,
          })
      if token_wrapper.get('refresh_token'):
        all_token_wrappers.append({
          'name': 'RT: '+token_wrapper['name'], 
          'type': 'refresh_token',
          'token': token_wrapper['refresh_token'],
          'app_id': token_wrapper['app_id'],
          'timestamp': token_wrapper_key,
          })
    
    # OAuth tokens
    for token_wrapper_key, token_wrapper in self.get('access_tokens', {}).items():
      if token_wrapper.get('access_token'):
        all_token_wrappers.append({
          'name': 'AT: '+token_wrapper['name'], 
          'type': 'access_token',
          'token': token_wrapper['access_token'],
          'app_id': token_wrapper['app_id'],
          'timestamp': token_wrapper_key,
          })
      if token_wrapper.get('refresh_token'):
        all_token_wrappers.append({
          'name': 'RT: '+token_wrapper['name'], 
          'type': 'refresh_token',
          'token': token_wrapper['refresh_token'],
          'app_id': token_wrapper['app_id'],
          'timestamp': token_wrapper_key,
          })

    # SAML assertions
    for token_wrapper_key, token_wrapper in self.get('saml_assertions', {}).items():
      all_token_wrappers.append({
        'name': 'SAML: '+token_wrapper['name'], 
        'type': 'saml_assertion',
        'token': token_wrapper['saml_assertion'],
        'app_id': token_wrapper['app_id'],
        'timestamp': token_wrapper_key,
        })

    return all_token_wrappers
    

  @property
  def context_id(self) -> str:
    return self['context_id']

  
  @property
  def idp_id(self) -> dict:
    return self['idp_id']

  
  @property
  def app_id(self) -> dict:
    return self['app_id']

  
  @property
  def idp_params(self) -> dict:
    """ Retourne le dictionnaire des paramètres de l'IdP
    
    Returns:
      dict
          
    Versions:
      05/09/2024 (mpham) version initiale
    """
    return self['idp_params']


  @property
  def app_params(self) -> dict:
    """ Retourne le dictionnaire des clients, donnant accès aux paramètres des applications correspondantes
    
    Returns:
      dict
          
    Versions:
      03/12/2024 (mpham) version initiale
    """
    return self['app_params']


  @property
  def last_app_params(self) -> dict:
    """ Retourne le dictionnaire des paramètres du client ayant réalisé la dernière authentification
    
    Returns:
      dict
          
    Versions:
      05/09/2024 (mpham) version initiale
    """
    return self['app_params'][self['app_id']]


  @property
  def last_api_params(self) -> dict:
    return self['api_params']
