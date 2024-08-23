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
      
    La structure de Context est de type JSON : organisation non contrainte de dict et list
      
    On conserve la requête initiale : endpoints, mots de passe, paramètres
      => context['initial_flow'] : dict
           avec les propriétés communes idp_id et app_id faisant référence à la configuration
                                        flow_type : OIDC, OAuth ou SAML
           les caractéristiques de l'IdP sont dans le dictionnaire context.initial_flow.idp
           la requête (client_id, etc.) est dans la propriété app_params
      
    Ainsi que les valeurs liées aux requêtes ultérieure (modifications apportées lors des cinématiques ultérieures)
      => context['current_flow']
      
    On garde aussi les différents jetons
      Ils sont indexés par leur nom : client_id + date d'obtention + circonstance (initial, token exchange)
      => context['id_tokens'] (avec les AT et RT associés)
      => context['access_tokens'] (on distingue les AT OAuth et les AT liés à des ID tokens)
        - context['access_tokens'] contient les AT obtenus par OAuth
        - get_all_access_tokens() retourne tous les AT, y compris ceux liés à des ID tokens
      => context['saml_assertions']
    
  Versions:
    08/08/2024 (mpham) version initiale
  """

  def __init__(self):
    self['context_id'] = str(uuid.uuid4())
    self['initial_flow'] = {}
    self['initial_flow']['idp_params'] = {}
    self['initial_flow']['app_params'] = {}
    self['current_flow'] = {}
    self['current_flow']['idp_params'] = {}
    self['current_flow']['app_params'] = {}
    self['id_tokens'] = {}
    self['access_tokens'] = {}
    self['saml_assertions'] = {}


  def get_all_access_tokens(self):
    # TODO
    return self.oauth_access_tokens