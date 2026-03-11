# -*- coding: utf-8 -*-
"""
Copyright 2023-2026 Aduneo

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

"""
  Dépendances :
    OpenSSL (génération d'une clé privée et d'un certificat)
    
  Args:
    host: adresse IP d'écoute du serveur, a priorité sur la valeur dans le fichier de configuration
    port: port d'écoute du serveur, a priorité sur la valeur dans le fichier de configuration
    root-dir: chemin du dossier où sont créés les dossiers conf et logs, le dossier courant par défaut
    tls: chiffrement de la connexion, a priorité sur la valeur dans le fichier de configuration. Pour désactiver TLS : -tls:no
    
  Si le fichier de configuration n'existe pas, il en est créé un par copie de clientfedid-template.cnf
    - si host, port et/ou tls sont donnés en paramètre, ils remplacent la valeur par défaut de clientfedid-template.cnf
    - si port n'est pas donné mais que TLS est désactivé, le port par défaut est 80
    
  Si le certificat (et la clé) SSL n'est pas donné dans le paramètre de configuration server/ssl_cert_file (et server/ssl_key_file)
    un certificat est généré
    
  Exemple :
    clientfedid -port 8080 -tls:no
  
"""
import os
import logging
import ssl
import time
import threading
from http.server import HTTPServer
from socketserver import ThreadingMixIn

from .Configuration import Configuration
from .CmdArgs import CmdArgs
args = CmdArgs({'host': 'string', 'port': 'int', 'tls': 'switch', 'root-dir': 'string', 'test[false]': 'switch'}).parsed_args

from .BaseServer import BaseServer
from .CryptoTools import CryptoTools
from .Server import Server
from .session.SessionManager import SessionManager


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


session_thread = None   # on conserve l'objet de thread pour l'arrêter au Ctrl-C 

def main():

  # Préparation de la configuration
  if 'root-dir' in args:
    Configuration.set_root_dir(args['root-dir'])
  
  # Récupération de la modification de la configuration de base par variable d'environnement puis par argument de commande en ligne
  overwrite_host = os.environ.get('CFI_LISTENING_HOST') if 'CFI_LISTENING_HOST' in os.environ else args.get('host') if 'host' in args else None
  overwrite_port = os.environ.get('CFI_LISTENING_PORT') if 'CFI_LISTENING_PORT' in os.environ else args.get('port') if 'port' in args else None
  if overwrite_port is not None:
    overwrite_port = int(overwrite_port)
  overwrite_tls = Configuration.is_on(os.environ.get('CFI_LISTENING_TLS')) if 'CFI_LISTENING_TLS' in os.environ else args.get('tls') if 'tls' in args else None


  # Lecture ou création (au premier lancement) du fichier de configuration , les arguments ne sont pris en compte que si un nouveau fichier est créé, pour l'initialiser
  conf = Configuration.read_configuration('clientfedid.cnf', listen_host=overwrite_host, listen_port=overwrite_port, tls=overwrite_tls)
  BaseServer.conf = conf
  
  log_method = conf['/preferences/logging/handler']
  result = Configuration.configure_logging(log_method)
  
  # Détermination de la configuration de base définitive, et journalisation (il a fallu attendre que le logger soit initialisé, d'où les redites)
  if 'CFI_LISTENING_HOST' in os.environ:
    host = overwrite_host
    logging.info(f"Server listening host set to {host} from environment variable CFI_LISTENING_HOST")
  elif 'host' in args:
    host = overwrite_host
    logging.info(f"Server listening host set to {host} from command line argument -host")
  else:
    host = conf['/server/host']
    logging.info(f"Server listening host set to {host} from configuration")
  # port
  if 'CFI_LISTENING_PORT' in os.environ:
    port = overwrite_port
    logging.info(f"Server listening port set to {port} from environment variable CFI_LISTENING_PORT")
  elif 'port' in args:
    port = overwrite_port
    logging.info(f"Server listening port set to {port} from command line argument -port")
  else:
    port = int(conf['/server/port'])
    logging.info(f"Server listening port set to {port} from configuration")
  # tls
  if 'CFI_LISTENING_TLS' in os.environ:
    tls = overwrite_tls
    logging.info(f"Server TLS set to {tls} from environment variable CFI_LISTENING_TLS")
  elif 'tls' in args:
    tls = overwrite_tls
    logging.info(f"Server TLS set to {tls} from command line argument -tls")
  else:
    tls = Configuration.is_parameter_on(conf, '/server/tls', True)
    logging.info(f"Server TLS set to {tls} from configuration")

  # On est passé en ThreadedHTTPServer et non en HTTPServer à cause de problèmes de connexion en mode incognito (https://bip.weizmann.ac.il/course/python/PyMOTW/PyMOTW/docs/BaseHTTPServer/index.html)
  httpd = ThreadedHTTPServer((host, port), Server)
  # Pour s'assurer que Ctrl-C fonctionne (https://blog.sverrirs.com/2016/11/simple-http-webserver-python.html)
  httpd.daemon_threads = True
  httpd.ssl_params = {}
  
  # SSL
  httpd.secure = tls
  if httpd.secure:
  
    conf_dir = Configuration.conf_dir
    
    if conf.get('/server/tls_cert_file') is None:
      CryptoTools.generate_temp_certificate(conf)
      httpd.ssl_params['key_temp_files'] = True
    else:
      cert_file_path = conf_dir+'/'+conf['/server/tls_cert_file']
      if not os.path.isfile(cert_file_path):
        if Configuration.is_parameter_on(conf, '/server/tls_generate_keys', False):
          logging.info('Certificate file '+conf['/server/tls_cert_file']+" does not exist, generating new TLS keys")
          CryptoTools.generate_self_signed_certificate(conf['/server/host'], conf_dir+'/'+conf['/server/tls_key_file'], conf_dir+'/'+conf['/server/tls_cert_file'])
        else:
          logging.info('Certificate file '+conf['/server/tls_cert_file']+" does not exist, server can't start")
          exit(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=conf_dir+'/'+conf['/server/tls_cert_file'], keyfile=conf_dir+'/'+conf['/server/tls_key_file'])
    
    httpd.ssl_params['server_private_key'] = conf['/server/tls_key_file']
    httpd.ssl_params['server_certificate'] = conf['/server/tls_cert_file']
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
  scheme = 'http'
  if httpd.secure:
    scheme = 'https'

  session_timer(conf)
  logging.info("----------------------------------")
  logging.info(f"Server UP - {scheme+'://'+host}:{port}")
  try:
      httpd.serve_forever()
  except KeyboardInterrupt:
      pass
  httpd.server_close()
  logging.info("----------------------------------")
  logging.info(f"Server DOWN - {scheme+'://'+host}:{port}")
  if (session_thread):
    session_thread.cancel()
  
  if httpd.ssl_params.get('key_temp_files'):
    os.unlink(conf_dir+'/'+conf['server']['ssl_key_file'])
    os.unlink(conf_dir+'/'+conf['server']['ssl_cert_file'])
    

def session_timer(conf):
  """ Déclenchement périodique du nettoyage des sessions
  
  Args:
    conf: configuration, qui est requise pour la récupération du singleton SessionManager
    
  Versions:
    17/02/2026 (mpham) version initiale
  """
  global session_thread
  if session_thread:
    session_manager = SessionManager(conf)
    session_manager.expire_sessions()
  session_thread = threading.Timer(60, session_timer, args=[conf])
  session_thread.start()


def test():
  print('--- test mode ----')
  
  from .test.TestMain import TestMain
  TestMain.test()

    
if __name__ == '__main__':
  if args.get('test'):
    test()
  else:
    main()
