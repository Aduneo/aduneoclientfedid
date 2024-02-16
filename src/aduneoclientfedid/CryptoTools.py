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
from cryptography.fernet import Fernet
from OpenSSL import crypto, SSL
import logging
import os
import random
import socket
import string
import tempfile

class CryptoTools:
  
  
  def __init__(self, key_file_path:str):
    """ Constructeur
    
    Si le fichier de clé n'existe pas, un clé est automatiquement générée
    
    Args:
      key_file_path: chemin complet d'un fichier de clé de chiffrement, qui doit être dans le dossier conf
      
    Raises:
      AduneoError si le fichier n'est pas dans le dossier conf
      
    Versions:
      28/12/2022 (mpham) : version initiale, copiée de CryptoConf.get_cipher()
    """
    self.key_file_path = key_file_path
    self.cipher = None
    
    conf_dir = os.path.join(os.getcwd(), 'conf')
    if not BaseServer.check_path_traversal(conf_dir, key_file_path):
      raise AduneoError('file '+key_file_path+' not in conf directory')
    
    if not os.path.isfile(key_file_path):
      print("encryption: key file not found, generating a new key")
      logging.info("encryption: key file not found, generating a new key")
      CryptoTools.generate_key(key_file_path)
      
  
  def generate_key_self_signed():
    
    """Génère un biclé RSA et retourne la clé et un certificat auto-signé en PEM
    
    :return: (clé privée en PEM, certificat autosigné en PEM)
    :rtype: (str, str)
    
    .. notes::
      mpham 21/05/2021
      mpham 06/06/2023 : on crée des certificats en version 3
    """

    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 4096)

    cert = crypto.X509()
    cert.set_version(2)
    cert.get_subject().C = 'FR'
    cert.get_subject().L = 'Paris'
    cert.get_subject().O = 'Aduneo'
    cert.get_subject().CN = 'ClientFedID'
    cert.get_subject().emailAddress = 'contact@aduneo.com'
    cert.set_serial_number(0)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, 'sha512')

    private_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode("utf-8")
    certificate = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
    
    return (private_key, certificate)
    
    
  def generate_temp_certificate(conf : dict):
    
    """Génère une biclé RSA et la stocke dans des fichiers temporaires du dossier conf
    Met le nom des fichiers dans les champs server/ssl_key_file et server/ssl_cert_file de l'objet de configuration
    
    :param conf: object JSON de configuration
    :type conf: dict
    
    .. notes::
      mpham 21/05/2021
      mpham 06/06/2023 : on crée des certificats en version 3
    """
    
    cn = conf['server'].get('host', '')
    if cn == '':
      cn = socket.getfqdn()
    
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 4096)
    
    cert = crypto.X509()
    cert.set_version(2)
    cert.get_subject().C = 'FR'
    cert.get_subject().L = 'Paris'
    cert.get_subject().O = 'Aduneo'
    cert.get_subject().CN = cn
    cert.get_subject().emailAddress = 'contact@aduneo.com'
    cert.set_serial_number(random.randrange(1208925819614629174706176))
    # Si on met un SAN, Google n'est pas content : localhost doesn't adhere to security standards. Si on l'omet, le certificat est invalide et Chrome (108 en tout cas) permet qu'on continue...
    #cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, ('DNS:'+cn).encode())])
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, 'sha512')

    conf_path = os.path.join(os.getcwd(), 'conf')
    
    fd, path = tempfile.mkstemp(prefix="temp_", dir=conf_path, text=True)
    with open(fd, 'w') as out_file:
      out_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode("utf-8"))
    conf['server']['ssl_key_file'] = os.path.basename(path)
      
    fd, path = tempfile.mkstemp(prefix="temp_", dir=conf_path, text=True)
    with open(fd, 'w') as out_file:
      out_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    conf['server']['ssl_cert_file'] = os.path.basename(path)
    

  def generate_self_signed_certificate(hostname:str, key_file_path:str, cert_file_path:str):
    """ Génère une biclé RSA et un certificat autosigné correspondant, pour un nom de serveur donné
    
    Enregistre la clé privée dans key_file_path et le certificat dans cert_file_path
    
    Args:
      hostname: nom de domaine de l'URL du certificat
      key_file_path: chemin complet du fichier recevant la clé privée
      cert_file_path: chemin complet du fichier recevant le certificat
      
    Versions:
      23/12/2022 (mpham) : version initiale
      03/03/2023 (mpham) : on retire le SAN, comme pour generate_temp_certificate
      06/06/2023 (mpham) : on crée des certificats en version 3
    """
    
    key_pair = crypto.PKey()
    key_pair.generate_key(crypto.TYPE_RSA, 4096)
    
    cert = crypto.X509()
    cert.set_version(2)
    cert.get_subject().C = 'FR'
    cert.get_subject().L = 'Paris'
    cert.get_subject().O = 'Aduneo'
    cert.get_subject().CN = hostname
    cert.get_subject().emailAddress = 'contact@aduneo.com'
    cert.set_serial_number(0)
    cert.set_serial_number(random.randrange(1208925819614629174706176))
    # Si on met un SAN, Google n'est pas content : localhost doesn't adhere to security standards. Si on l'omet, le certificat est invalide et Chrome (108 en tout cas) permet qu'on continue...
    #cert.add_extensions([crypto.X509Extension(b"subjectAltName", False, ('DNS:'+hostname).encode())])
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(key_pair)
    cert.sign(key_pair, 'sha512')

    conf_path = os.path.join(os.getcwd(), 'conf')
    
    with open(key_file_path, 'w') as out_file:
      out_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key_pair).decode("utf-8"))
      
    with open(cert_file_path, 'w') as out_file:
      out_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8"))
    

  def _get_cipher(self):
    """ Retourne un objet de chiffrement de type Fernet
      
      Se base sur une clé présente dans un fichier référencé dans le paramètre de configuration /meta/key (nom du fichier cherché dans le dossier conf)
      
      Si le fichier n'existe, il est créé une clé.
      
      L'objet de chiffrement est conservé dans self.cipher pour n'avoir à en créer un qu'une seule fois au lancement du programme
      
      Returns:
        objet de chiffrement Fernet
        
      Raises:
        AduneoError si le fichier n'est pas dans le dossier conf
        
      Versions:
        00/00/2021 (mpham) : version initiale
        23/12/2022 (mpham) : création automatique de la clé si elle n'existe pas
        28/12/2022 (mpham) : déplacement depuis Configuration
    """
    
    if self.cipher is None:
      
      if not os.path.isfile(self.key_file_path):
        print("encryption: key file not found, generating a new key")
        ConfCrypto.generate_key(self.key_file_path)

      file_in = open(self.key_file_path, 'r')
      key = file_in.read()
      file_in.close
      key = key[:5]+key[11:]
      
      self.cipher = Fernet(key.encode('ascii'))
      
    return self.cipher
  
  
  def decrypt_string(self, string:str) -> str:
    """ Déchiffre une chaîne de caractères

      Args:
        string: chaîne de caractères à déchiffrer
      
      Returns:
        texte déchiffré
        
      Raises:
        AduneoError si le fichier n'est pas dans le dossier conf
        
      Versions:
        00/00/2021 (mpham) : version initiale
        28/12/2022 (mpham) : déplacement depuis Configuration
    """
    token = string.encode('ascii')
    decrypted_token = self._get_cipher().decrypt(token)
    return decrypted_token.decode('UTF-8')
    
    
  def encrypt_string(self, text:str) -> str:
    """ Chiffre un texte

      Args:
        text: texte à chiffrer
      
      Returns:
        chaîne de caractères contenant le texte chiffré
        
      Raises:
        AduneoError si le fichier n'est pas dans le dossier conf
        
      Versions:
        00/00/2021 (mpham) : version initiale
        28/12/2022 (mpham) : déplacement depuis Configuration
    """
    token = self._get_cipher().encrypt(text.encode('UTF-8'))
    return token.decode('ascii')

  
  def generate_key(key_file_path:str):
    """ Génère un fichier de clé utilisable par get_cipher
    
    Ecrase le fichier s'il existe déjà
    
    Args
      key_file_path: chemin complet du fichier recevant la clé
    
    Raises:
      exception d'ouverture de fichier en écriture
    
    Versions:
      23/12/2022 (mpham) : version initiale
    """

    key = Fernet.generate_key()
    key_string = key.decode('ascii')
    iv = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))
    
    file_out = open(key_file_path, 'w')
    file_out.write(key_string[:5]+iv+key_string[5:])
    file_out.close()


