# -*- coding: utf-8 -*-
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

"""
  Dépendances :
    OpenSSL (génération d'une clé privée et d'un certificat)
    
  Si le certificat (et la clé) SSL n'est pas donné dans le paramètre de configuration server/ssl_cert_file (et server/ssl_key_file)
    un certificat temporaire est généré
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
# Regarde s'il faut initialiser un nouveau fichier de configuration
args = CmdArgs({'host': 'string', 'port': 'int', 'test': 'switch'}).parsed_args
if not os.path.isfile(os.path.join(os.getcwd(), 'conf', 'clientfedid.cnf')):
  Configuration.read_configuration('clientfedid.cnf', listen_host=args.get('host'), listen_port=args.get('port'))

from .CryptoTools import CryptoTools
from .Server import Server



class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
    

def main():

  conf = Configuration.read_configuration('clientfedid.cnf')
  
  log_method = conf['preferences']['logging']['handler']
  result = Configuration.configure_logging(log_method)
  
  host = args.get('host') if 'host' in args else conf['server']['host']
  port = args.get('port') if 'port' in args else int(conf['server']['port'])

  # On est passé en ThreadedHTTPServer et non en HTTPServer à cause de problèmes de connexion en mode incognito (https://bip.weizmann.ac.il/course/python/PyMOTW/PyMOTW/docs/BaseHTTPServer/index.html)
  httpd = ThreadedHTTPServer((host, port), Server)
  # Pour s'assurer que Ctrl-C fonctionne (https://blog.sverrirs.com/2016/11/simple-http-webserver-python.html)
  httpd.daemon_threads = True
  httpd.ssl_params = {}
  
  # SSL
  httpd.secure = False
  if Configuration.is_on(conf['server']['ssl']):
  
    httpd.secure = True
    conf_dir = os.path.join(os.getcwd(), 'conf')
    conf_dir = Configuration.conf_dir
    
    if conf['server'].get('ssl_cert_file', '') == "":
      CryptoTools.generate_temp_certificate(conf)
      httpd.ssl_params['key_temp_files'] = True
    else:
      cert_file_path = conf_dir+'/'+conf['server']['ssl_cert_file']
      if not os.path.isfile(cert_file_path):
        if Configuration.is_parameter_on(conf, '/server/ssl_generate_keys', False):
          print('Certificate file '+conf['server']['ssl_cert_file']+" does not exist, generating new SSL keys")
          CryptoTools.generate_self_signed_certificate(conf['server']['host'], conf_dir+'/'+conf['server']['ssl_key_file'], conf_dir+'/'+conf['server']['ssl_cert_file'])
        else:
          print('Certificate file '+conf['server']['ssl_cert_file']+" does not exist, server can't start")
          exit(1)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=conf_dir+'/'+conf['server']['ssl_cert_file'], keyfile=conf_dir+'/'+conf['server']['ssl_key_file'])
    
    httpd.ssl_params['server_private_key'] = conf['server']['ssl_key_file']
    httpd.ssl_params['server_certificate'] = conf['server']['ssl_cert_file']
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
  scheme = 'http'
  if httpd.secure:
    scheme = 'https'

  print(time.asctime(), 'Server UP - %s:%s' % (scheme+'://'+host, port))
  try:
      httpd.serve_forever()
  except KeyboardInterrupt:
      pass
  httpd.server_close()
  print(time.asctime(), 'Server DOWN - %s:%s' % (scheme+'://'+host, port))
  
  if httpd.ssl_params.get('key_temp_files'):
    os.unlink(conf_dir+'/'+conf['server']['ssl_key_file'])
    os.unlink(conf_dir+'/'+conf['server']['ssl_cert_file'])
    

def test():
  print('--- test mode ----')
  
  from .test.TestMain import TestMain
  TestMain.test()

    
if __name__ == '__main__':
  if args.get('test'):
    test()
  else:
    main()
