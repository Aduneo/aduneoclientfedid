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
from .BaseServer import BaseServer
from .CryptoTools import CryptoTools
from .WebConsoleHandler import WebConsoleHandler
from datetime import datetime
import copy
import json
import logging
import random
import os
import string
import sys


class conf_dict(dict):
  """ dict personnalisé pour la configuration, donnant un accès direct à une clé dans un arbre
  
  Le chemin d'une valeur est donné par la liste des clés depuis la racine, séparées par des barres obliques (/)
  
  Par exemple : preferences/jwt/library
  
  L'accès est possible par :
    - les crochets : conf['clé']
    - get : conf.get('clé', 'valeur par défaut')
  
  Versions:
    22/12/2023 (mpham) version initiale
  """
  
  def copy(d:dict) -> dict:
    """ Réalise une copie d'un dictionnaire en conf_dict
    en itérant à tous les niveaux
    
    Args:
      d: dictionnaire à traduire
      
    Returns;
      un conf_dict avec le même contenu que dans
      
    Versions:
      22/12/2023 (mpham) version initiale
    """
  
    copy = conf_dict()
    for (key, value) in d.items():
    
      if isinstance(value, dict):
        copy[key] = conf_dict.copy(value)
      else:
        copy[key] = value
    
    return copy


  def __getitem__(self, path:str):
    """ obtention de la valeur d'une clé, par les crochets []
      soit une clé au premier niveau (par de / dans le chemin), avec le même comportement que []
      soit une clé dans le sous-arbre (le chemin étant donné par les clés séparées par des /)
      
    Lève une exception si la valeur ne peut être trouvé (clé ou chemin invalide)
      
    Args:
      path: chemin des clés dans le sous-arbre, s'il commence par un / il est ignoré
      
    Returns:
      valeur de la clé
      
    Versions:
      22/12/2023 (mpham) version initiale
    """
    
    if path.startswith('/'):
      path = path[1:]
    if path.find('/') >= 0:
      d = self
      for key in path.split('/'):
        d = d[key]
      value = d
    else:
      value = super().__getitem__(path)
      
    return value

  
  def get(self, path:str, default=None):
    """ obtention de la valeur d'une clé, par la méthode get
      soit une clé au premier niveau (par de / dans le chemin), avec le même comportement que []
      soit une clé dans le sous-arbre (le chemin étant donné par les clés séparées par des /)
      
    Retourne la valeur par défaut si la valeur ne peut être trouvé (clé ou chemin invalide)
      
    Args:
      path: chemin des clés dans le sous-arbre, s'il commence par un / il est ignoré
      default: valeur par défaut (None si pas donnée) retournée si la clé n'est pas trouvée

    Returns:
      valeur de la clé si elle peut être récupérée, la valeur par défaut sinon
      
    Versions:
      22/12/2023 (mpham) version initiale
    """
    
    value = default
    
    if path.startswith('/'):
      path = path[1:]
    d = self
    try:
      for key in path.split('/'):
        d = d[key]
      value = d
    except:
      pass
    
    return value
    

  def is_on(self, path:str, default:bool=False):
    """ Indique si un paramètre de configuration est true (au sens Configuration.is_on)
    
    Le paramètre est donné par son chemin dans le fichier JSON, par exemple /preferences/open_webconsole
    
    Si le paramètre n'est pas trouvé, une valeur par défaut est retournée, qu'elle ait été fournie en entrée ou qu'il s'agisse de False sinon.
    
    Args:
      path (str): chemin du paramètre à partir de la racine, en séparant les éléments par un slash (barre oblique /). Exemple : preferences/jwt/library
      default: valeur par défaut (optionnelle)
      
    Returns:
      True si la valeur du paramètre est vraie selon is_on, False sinon
      La valeur par défaut si la paramètre n'a pas pu être trouvé dans la configuration

    mpham 22/12/2023
    """
    
    value = self.get(path, default)
    if not isinstance(value, bool):
      value = Configuration.is_on(value)
      
    return value
      
    
  def is_off(self, path:str, default:bool=False):
    """ Indique si un paramètre de configuration est faux (au sens Configuration.is_on)
    
    Le paramètre est donné par son chemin dans le fichier JSON, par exemple /preferences/open_webconsole
    
    Si le paramètre n'est pas trouvé, une valeur par défaut est retournée, qu'elle ait été fournie en entrée ou qu'il s'agisse de False sinon.
    
    Args:
      path (str): chemin du paramètre à partir de la racine, en séparant les éléments par un slash (barre oblique /). Exemple : preferences/jwt/library
      default: valeur par défaut (optionnelle)
      
    Returns:
      True si la valeur du paramètre est fausse selon is_off, False sinon
      La valeur par défaut si la paramètre n'a pas pu être trouvé dans la configuration

    mpham 22/12/2023
    """
    
    value = self.get(path, default)
    if not isinstance(value, bool):
      value = Configuration.is_off(value)
      
    return value
      
    

class Configuration():

  conf_dir = os.path.join(os.getcwd(), 'conf')

  def read_configuration(conf_filename, listen_host:str=None, listen_port:int=None):
    """
    Lit un fichier de configuration JSON du répertoire conf (lu dans le dossier en cours, celui d'où a été lancée la commande python -m ClientFedID)
    Met le nom du fichier dans /meta/filename
    
    S'il n'existe pas de fichier de configuration, une copie de data/clientfedid-template.cnf est réalisée et mise dans conf
    
    Args:
      conf_filename: nom court du fichier de configuration
      port: port d'écoute du serveur, utilisé lors de l'initialisation du fichier de configuration au premier démarrage (n'est plus utilisé ensuite)
    
    Versions:
      26/02/2021 (mpham) version initiale
      29/12/2022 (mpham) dissociation des dossiers conf (retiré du module) et data (qui reste dans le module)
      25/01/2023 (mpham) initialisation du host et du port d'écoute lors de l'initialisation du fichier de configuration à partir de clientfedid-template.cnf
      08/08/2024 (mpham) version 2 de la configuration
    """

    if not os.path.isdir(Configuration.conf_dir):
      os.mkdir(Configuration.conf_dir)
    
    conf_filepath = os.path.join(Configuration.conf_dir, conf_filename)

    create_from_template = False
    if conf_filename not in os.listdir(Configuration.conf_dir):
      data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'data')
      if 'clientfedid-template.cnf' not in os.listdir(data_dir):
        raise AduneoError('file '+conf_filename+' not in conf directory and and clientfedid-template.cnf not in data directory')
      else:
        with open(os.path.join(data_dir, 'clientfedid-template.cnf'), 'r') as template_file:
          with open(conf_filepath, 'w') as file:
            file.write(template_file.read())
        create_from_template = True

    crypto = ConfCrypto()
    crypto.read(conf_filepath)

    if not crypto.app_conf['meta'].get('version'):
      # on est en version 1, il faut convertir le fichier en version 2
      crypto.convert_1to2()
      crypto.write()
    elif create_from_template:
      if listen_host:
        crypto.app_conf['server']['host'] = listen_host
      if listen_port:
        crypto.app_conf['server']['port'] = str(listen_port)
      crypto.write()
    
    return crypto.app_conf
  

  def write_configuration(conf):

    """
    Enregistre un JSON de configuration
    Le nom du fichier est dans /meta/filename
    
    mpham 27/02/2021
    """
    
    crypto = ConfCrypto()
    crypto.set_conf(conf)
    crypto.write()
    #crypto = ConfCrypto(conf_filepath)
    #return crypto.decrypt()
  

  def is_on(value):
    
    """
    Indique si une valeur (a prioiri issue d'un fichier de configuration) est vraie :
    on, yes, true, oui
    
    mpham 26/02/2021
    """
    
    return value.lower() in ('on', 'yes', 'true', 'oui')
    

  def is_off(value):
    
    """
    Indique si une valeur (a prioiri issue d'un fichier de configuration) est false :
    off, no, false, non
    
    mpham 26/02/2021
    """
    
    return value.lower() in ('off', 'no', 'false', 'non')



  def is_parameter_on(conf:dict, path:str, default:bool = False):
    """ Indique si un paramètre de configuration est true (au sens Configuration.is_on)
    
    Le paramètre est donné par son chemin dans le fichier JSON, par exemple /preferences/open_webconsole
    
    Si le paramètre n'est pas trouvé, une valeur par défaut est retournée, qu'elle ait été fournie en entrée ou qu'il s'agisse de False sinon.
    
    Args:
      conf (dict): une configuration issue de self.read_configuration
      path (str): chemin du paramètre à partir de la racine, en séparant les éléments par un slash (barre oblique /). Exemple : preferences/jwt/library
      default: valeur par défaut (optionnelle)
      
    Returns:
      True si la valeur du paramètre est vraie selon is_on, False sinon
      La valeur par défaut si la paramètre n'a pas pu être trouvé dans la configuration

    mpham 19/12/2022
    """
    
    value = default
    
    if path.startswith('/'):
      path = path[1:]
      
    go_on = True
    for item in path.split('/'):
      if go_on:
        conf = conf.get(item)
        if conf is None:
          go_on = False
          
    if conf:
      value = Configuration.is_on(conf)
    
    return value
  

  def configure_logging(log_method: list):
    global WEB_CONSOLE_BUFFER
    WEB_CONSOLE_BUFFER = []
    handler_list = []

    if "file" in log_method:
      date = datetime.today().strftime('%Y-%m-%d')
      log_dir = os.path.join(os.getcwd(), 'logs')
      log_file = os.path.join(log_dir, 'ClientFedID-{}.log'.format(date))
      if not os.path.isdir(log_dir):
        os.mkdir(log_dir)
      if not os.path.isfile(log_file):
        with open(log_file, 'w') as f:
          f.close()

      hdlr = logging.FileHandler(
        filename=log_file,
        encoding='utf-8'
        )
      hdlr.setLevel(logging.DEBUG)
      handler_list.append(hdlr)

    if "web_console" in log_method:
      hdlr  = WebConsoleHandler()
      hdlr.setLevel(logging.INFO)
      hdlr.setFormatter(logging.Formatter('%(asctime)s: %(message)s', "%H:%M:%S"))
      handler_list.append(hdlr)
    if "console" in log_method:
      hdlr = logging.StreamHandler(sys.stdout)
      hdlr.setLevel(logging.DEBUG)
      handler_list.append(hdlr)
    if "rsyslog" in log_method:
      '''
      hdlr  = logging.handlers.SysLogHandler(address="127.0.0.1", 6666)
      hdlr.setLevel(logging.DEBUG)
      handler_list.append(hdlr)
      '''
      pass
    if not handler_list:
      return False

    logging.basicConfig(
      #encoding='utf-8',  # retiré pour compatibilité Python 3.6
      level=logging.DEBUG,
      format="%(asctime)s:%(levelname)s:%(message)s",
      handlers=handler_list
      )

    return True
    

class ConfCrypto():

  def __init__(self):
    
    self.app_conf = None
    self.file_conf = None
    self.crypto = None # ne pas y accéder directement, à récupérer par _get_crypto()
    self.modification = False


  def read(self, conf_filepath):

    self.conf_filepath = conf_filepath
    self.cipher = None
    self.modification = False
    
    with open(conf_filepath) as json_file:
      self.file_conf = json.load(json_file)
    
    if not 'meta' in self.file_conf:
      self.file_conf['meta'] = {}
    self.file_conf['meta']['filename'] = os.path.basename(conf_filepath)
    
    self.decrypt()
    
  
  def set_conf(self, conf):
    
    self.app_conf = conf
    
  
  def decrypt(self):
    """ Déchiffre les secrets contenus dans le fichier de configuration et met le fichier à jour si des secrets en clair sont trouvés
    
    Versions:
      00/00/2021 (mpham) version initiale
      22/12/2023 (mpham) la configuration n'est plus un dict, mais un conf_dict
      17/02/2024 (mpham) conversion de valeur de token_endpoint_auth_method
      28/02/2025 (mpham) adaptation de la conversion de valeur de token_endpoint_auth_method
    """

    self.app_conf = conf_dict.copy(self.file_conf)
    self.decrypt_json(self.app_conf)
    
    if self.modification:
      self.write()
    
    
  def decrypt_json(self, data):
    
    if isinstance(data, dict):
    
      for key in list(data.keys()):
        value = data[key]
        if key.endswith('!'):
          if not isinstance(value, str):
            raise AduneoError('key '+key+' has not a string value')
            
          # on regarde si la valeur est déjà chiffrée
          if value.startswith('{Fernet}'):
            data[key] = self._get_crypto().decrypt_string(value[8:])           
          else:
            self.modification = True
        elif key == 'token_endpoint_auth_method':
          # Conversion de valeur de février 2024 - modifiée le 28 février 2025
          if value in ['basic', 'Basic', 'POST', 'client_secret_basic', 'client_secret_post']:
            data[key] = {'Basic': 'basic', 'basic': 'basic', 'POST': 'form', 'client_secret_basic': 'basic', 'client_secret_post': 'form'}[value]
            self.modification = True
        else:
          self.decrypt_json(value)
    elif isinstance(data, list):
      for item in data:
        self.decrypt_json(item)


  def encrypt_json(self, data):

    if isinstance(data, dict):
      for key in list(data.keys()):
        value = data[key]
        if key.endswith('!'):
          if not isinstance(value, str):
            raise AduneoError('key '+key+' has not a string value')
            
          # on regarde si la valeur est déjà chiffrée
          if not value.startswith('{Fernet}'):
            data[key] = '{Fernet}'+self._get_crypto().encrypt_string(value)
        else:
          self.encrypt_json(value)
    elif isinstance(data, list):
      for item in data:
        self.encrypt_json(item)

    
  def write(self):
  
    self.file_conf = copy.deepcopy(self.app_conf)
    del self.file_conf['meta']['filename']
    self.encrypt_json(self.file_conf)
    
    conf_filepath = Configuration.conf_dir + '/' + self.app_conf['meta']['filename']
    
    temp_filepath = conf_filepath+'.tmp'
    with open(temp_filepath, "w") as outfile: 
      json.dump(self.file_conf, outfile, indent=2)
      
    os.replace(temp_filepath, conf_filepath)
    
    
  def _get_crypto(self) -> CryptoTools:
    """ Retourne un objet de chiffrement
    
    Returns:
      objet de chiffrement
      
    Versions:
      28/12/2022 (mpham) : version initiale, adaptée de l'ancien get_cipher()
    """
    
    if not self.crypto:
  
      key_filename = None
      if 'meta' in self.file_conf:
        if 'key' in self.file_conf['meta']:
          key_filename = self.file_conf['meta']['key']
          
      if key_filename is None: 
        raise AduneoError('encryption: key file name not found in configuration (should be in /meta/key')
  
      key_file_path = Configuration.conf_dir+'/'+key_filename
  
      self.crypto = CryptoTools(key_file_path)
      
    return self.crypto


  def convert_1to2(self):
    """ Convertit un fichier de configuration de la version 1 à la version 2
    
    Versions
      08/08/2024 (mpham) version initiale
    """
    
    self.app_conf['meta']['version'] = 2
    self.app_conf['default'] = {
      "saml": {
        "idp_authentication_binding_capabilities": [
          "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ],
        "idp_logout_binding_capabilities": [
          "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
          "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        ]
      }
    }

    if self.app_conf.get('oidc_clients'):
      self._convert_1to2_oidc()
    if self.app_conf.get('oauth_clients'):
      self._convert_1to2_oauth2()
    if self.app_conf.get('saml_clients'):
      self._convert_1to2_saml()
    
  
  def _convert_1to2_oidc(self):
    """ Convertit les clients OIDC v1 en des ensembles IdP + client v2
    
    Versions
      08/08/2024 (mpham) version initiale
      23/12/2024 (mpham) changement des valeurs de endpoint_configuration et signature_key_configuration (Discovery URI -> discovery_uri par exemple)
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (oidc_<idp_id>_<app_id>) pour les rendre globalement uniques. Les IdP sont en idp_<ipd_id>
    """
    
    if not self.app_conf.get('idps'):
      self.app_conf['idps'] = {}
      
    for v1_client_id in self.app_conf['oidc_clients']:
      
      v1_client = self.app_conf['oidc_clients'][v1_client_id]
      
      v2_idp = {}
      for key in ['endpoint_configuration', 'discovery_uri', 'authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
        if v1_client.get(key):
          value = v1_client[key]
          if key == 'endpoint_configuration' or key == 'signature_key_configuration':
            if value == 'Discovery URI':
              value = 'discovery_uri'
            elif value == 'JWKS URI':
              value = 'discovery_uri'
            elif value == 'Local configuration':
              value = 'local_configuration'
          v2_idp[key] = value
      
      v2_client = {'name': 'OIDC Client'}
      for key in ['client_id', 'client_secret!', 'scope', 'response_type', 'redirect_uri', 'fetch_userinfo']:
        if v1_client.get(key):
          v2_client[key] = v1_client[key]
      
      v2_idp_id = self._check_unicity(f'idp_{v1_client_id}', self.app_conf['idps'].keys())
      
      self.app_conf['idps'][v2_idp_id] = {
        'name': v1_client['name'],
        'idp_parameters': {
          'oidc': v2_idp,
          'verify_certificates': v1_client.get('verify_certificates', 'on'),
        },
        'oidc_clients': {
          f'oidc_{v2_idp_id[4:]}_client': v2_client
        },
      }
      
    del self.app_conf['oidc_clients']
      
    
  def _convert_1to2_oauth2(self):
    """ Convertit les clients OAuth 2 v1 en des ensembles IdP + client v2
    
    Versions
      08/08/2024 (mpham) version initiale
      23/08/2024 (mpham) en OAuth 2, la valeur Discovery URI de l'aiguillage de configuration des endpoints devient Authorization Server Metadata URI
      23/12/2024 (mpham) changement des valeurs de endpoint_configuration et signature_key_configuration (Discovery URI -> metadata_uri par exemple)
      25/12/2024 (mpham) verify_certificates est remonté au niveau de idp_params
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (oauth2_<idp_id>_<app_id>) pour les rendre globalement uniques. Les IdP sont en idp_<ipd_id>
    """
    
    if not self.app_conf.get('idps'):
      self.app_conf['idps'] = {}
      
    for v1_client_id in self.app_conf['oauth_clients']:
      
      v1_client = self.app_conf['oauth_clients'][v1_client_id]
      
      v2_idp = {}
      for key in ['endpoint_configuration', 'discovery_uri', 'authorization_endpoint', 'token_endpoint', 'introspect_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key']:
        if v1_client.get(key):
          value = v1_client[key]
        
          v2_key = key
          if key == 'discovery_uri':
            v2_key = 'metadata_uri'
        
          v2_idp[v2_key] = v1_client[key]
          
          if key == 'endpoint_configuration' and v1_client[key] == 'Discovery URI':
            v2_idp[v2_key] = 'metadata_uri'
          elif key == 'endpoint_configuration' or key == 'signature_key_configuration':
            if value == 'JWKS URI':
              v2_idp[v2_key] = 'discovery_uri'
            elif value == 'Local configuration':
              v2_idp[v2_key] = 'local_configuration'
      
      v2_client = {'name': 'OAuth2 Client'}
      for key in ['client_id', 'client_secret!', 'scope', 'response_type', 'redirect_uri']:
        if v1_client.get(key):
          v2_client[key] = v1_client[key]
      
      v2_idp_id = self._check_unicity(f'idp_{v1_client_id}', self.app_conf['idps'].keys())
      
      self.app_conf['idps'][v2_idp_id] = {
        'name': v1_client['name'],
        'idp_parameters': {
          'oauth2': v2_idp,
          'verify_certificates': v1_client.get('verify_certificates', 'on'),
        },
        'oauth2_clients': {
          f'oauth2_{v2_idp_id[4:]}_client': v2_client
        },
      }
      
      if v1_client.get('rs_client_id'):
        self.app_conf['idps'][v2_idp_id]['oauth2_apis'] = {}
        self.app_conf['idps'][v2_idp_id]['oauth2_apis']['api'] = {
          'rs_client_id': v1_client['rs_client_id'],
          'rs_client_secret!': v1_client['rs_client_secret!']
        }
      
    del self.app_conf['oauth_clients']


  def _convert_1to2_saml(self):
    """ Convertit les clients SAML v1 en des ensembles IdP + client v2
    
    Versions
      08/08/2024 (mpham) version initiale
      31/12/2024 (mpham) les identifiants des apps sont maintenant préfixés (oauth2_<idp_id>_<app_id>) pour les rendre globalement uniques. Les IdP sont en idp_<ipd_id>
    """
    
    if not self.app_conf.get('idps'):
      self.app_conf['idps'] = {}
      
    for v1_client_id in self.app_conf['saml_clients']:
      
      v1_client = self.app_conf['saml_clients'][v1_client_id]
      
      v2_idp = {}
      for key in ['idp_entity_id', 'idp_certificate', 'idp_sso_url', 'idp_slo_url', 'verify_certificates']:
        if v1_client.get(key):
          v2_idp[key] = v1_client[key]
      
      v2_client = {'name': 'SAML SP'}
      for key in ['sp_entity_id', 'sp_acs_url', 'authentication_binding', 'logout_binding', 'sign_auth_request', 'sign_logout_request', 'sp_key_configuration', 'nameid_policy', 'sp_private_key', 'sp_certificate', 'sp_slo_url']:
        if v1_client.get(key):
          v2_client[key] = v1_client[key]
      
      v2_idp_id = self._check_unicity(f'idp_{v1_client_id}', self.app_conf['idps'].keys())
      
      self.app_conf['idps'][v2_idp_id] = {
        'name': v1_client['name'],
        'idp_parameters': {
          'saml': v2_idp,
        },
        'saml_clients': {
          f'saml_{v2_idp_id[4:]}_client': v2_client
        }
      }
      
    del self.app_conf['saml_clients']
      
    
  def _check_unicity(self, id:str, existing:list) -> str:
    """ Vérifie qu'un identifiant est bien unique et n'existe pas déjà dans un liste
    
    si ce n'est pas le cas, retourne un identifiant non présent dans la liste, construit à partir
      de l'identifiant à vérifier auquel on ajoute _ et un numéro

    Versions
      08/08/2024 (mpham) version initiale
    """

    unique_id = id
    
    sequence = 1
    while unique_id in existing:
      sequence += 1
      unique_id = f"{id}_{sequence}"
    
    return unique_id