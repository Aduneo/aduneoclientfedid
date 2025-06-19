"""
Copyright 2025 Aduneo

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

import base64
import logging
import ssl
import urllib3

from .BaseServer import AduneoError


class WebRequest():
  """ Réalise des requêtes auprès d'un serveur web
  
  A la manière de requests, mais avec la possibilité de faire du DNS override
  
  S'appuie sur urllib3
  
  Versions:
    04/06/2025 (mpham) version initiale
    12/06/2025 (mpham) en DNS override, possibilité de rediriger le port. <nom> pour rediriger l'adresse uniquement, :<port> pour redirifer le port et <nom>:<port> pour les deux
  """
  
  def get(url:str, query:dict={}, headers={}, basic_auth:tuple=None, verify_certificate:bool=True, dns_override:str=None):
    return WebRequest._request('GET', url, fields=query, raw_data=None, headers=headers, basic_auth=basic_auth, verify_certificate=verify_certificate, dns_override=dns_override)
  

  def post(url:str, form:dict=None, raw_data:str=None, headers={}, basic_auth:tuple=None, verify_certificate:bool=True, dns_override:str=None):
    return WebRequest._request('POST', url, fields=form, raw_data=raw_data, headers=headers, basic_auth=basic_auth, verify_certificate=verify_certificate, dns_override=dns_override)

    
  def _request(method:str, url:str, fields:dict=None, raw_data:str=None, headers={}, basic_auth:tuple=None, verify_certificate:bool=True, dns_override:str=None):

    parsed_url = urllib3.util.parse_url(url)
    
    pool = None
    request_url = None
    assert_same_host = True
    if not dns_override:
      # appel normal, on prend le pool normal
      pool = urllib3.PoolManager(cert_reqs=None if verify_certificate else 'CERT_NONE')
      request_url = url
    else:
      # appel en remplacement de DNS, on suit la documentation : https://urllib3.readthedocs.io/en/stable/advanced-usage.html#custom-sni-hostname
      headers['Host'] = parsed_url.host

      host = parsed_url.host
      port = str(parsed_url.port)
      colon_pos = dns_override.find(':')
      if colon_pos == 0:
        # redirection de port uniquement
        port = dns_override[colon_pos+1:]
      elif colon_pos > 0:
        # redirection de port et d'adresse
        host = dns_override[:colon_pos]
        port = dns_override[colon_pos+1:]
      else:
        # redirection d'adresse uniquement
        host = dns_override

      if parsed_url.scheme == 'http':
        pool = urllib3.HTTPConnectionPool(host, port)
        if parsed_url.port != 80:
          headers['Host'] += ':'+str(parsed_url.port)
      elif parsed_url.scheme == 'https':
        pool = urllib3.HTTPSConnectionPool(host, port, server_hostname=parsed_url.host, cert_reqs=None if verify_certificate else 'CERT_NONE')
        if parsed_url.port != 443:
          headers['Host'] += ':'+str(parsed_url.port)
        
      request_url = parsed_url.path
      if request_url is None:
        request_url = '/'
      assert_same_host = False
  
    if basic_auth:
      headers['Authorization'] = "Basic " + base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
    
    return pool.request(method, request_url, fields=fields, body=raw_data, headers=headers, assert_same_host=assert_same_host)
  
    

