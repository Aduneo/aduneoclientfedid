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
      26/02/2021 (mpham) : version initiale
      29/12/2022 (mpham) : dissociation des dossiers conf (retiré du module) et data (qui reste dans le module)
      25/01/2023 (mpham) : initialisation du host et du port d'écoute lors de l'initialisation du fichier de configuration à partir de clientfedid-template.cnf
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
        with open(os.path.join(data_dir, 'clientfedid-template.cnf'), 'r') as sample:
          with open(conf_filepath, 'w') as file:
            file.write(sample.read())
        create_from_template = True

    crypto = ConfCrypto()
    crypto.read(conf_filepath)
    
    if create_from_template:
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
      default (bool): valeur par défaut (optionnelle)
      
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

    
    
    
class ConfCrypto:
  
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
      00/00/2021 (mpham) : version initiale
    """
    
    self.app_conf = copy.deepcopy(self.file_conf)
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
  