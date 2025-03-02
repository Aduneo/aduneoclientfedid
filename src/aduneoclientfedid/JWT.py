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
import base64
import json

from .BaseServer import AduneoError


jwt_libraries = []
try:
  import jwcrypto
  jwt_libraries.append('jwcrypto')
except:
  pass


class JWT():
  """ Classe d'encapsulation des JWT (RFC 7519)
  
  Permet de s'appuyer sur diverses manières de représenter un JWT et surtout de vérifier les signatures / déchiffrer les JWE
  
  La méthode est définie dans la configuration, dans le paramètre preferences/jwt/library, avec pour valeurs possibles :
  - jwcrypto (par défaut si le paramètre n'est pas défini)
  - aduneo
  
  Versions:
    22/12/2023 (mpham) version initiale
    28/08/2024 (mpham) méthode statique is_jwt
  """

  def is_jwt(token:str) -> bool:
    """ Détermine si la chaîne ressemble à un JWT
    
    Args:
      token: chaîne de caractères à tester
      
    Versions:
      28/08/2024 (mpham) version initiale
    """

    result = False

    try:
      jwt = JWT(token)
      result = True
    except Exception as e:
      pass
    
    return result
    

  def __init__(self, token:str):
    """ Constructeur
    
    Vérifie que les prérequis sont bien requis pour les opérations (vérification de signature en particulier)
    
    Les membres suivants sont initialisés :
      self.header
      self.payload
      self.b64_signature
    
    Args:
      token: jeton en représentation JWT (par exemple eyJ[...]SJ9.eyJ[...]In0.Oj4[...]lMw)

    Versions:
      22/12/2023 (mpham) version initiale
      28/08/2024 (mpham) analyse du JWT
    """

    from .Server import Server # pour éviter les références circulaires
    self.conf = Server.conf

    # analyse du jeton
    dot_pos = token.find('.')
    if dot_pos == -1:
      raise AduneoError(f"token {token} is not a JWT, dot separator not found")

    b64_header = token[:dot_pos]
    try:
      json_header = base64.urlsafe_b64decode(b64_header + '=' * (4 - len(b64_header) % 4))
    except:
      raise AduneoError(f"token {token} is not a JWT, header {b64_header} not Base 64 URL encoded")
    
    try:
      self.header = json.loads(json_header)
    except:
      raise AduneoError(f"token {token} is not a JWT, header {json_header} not JSON encoded")
      
    rest = token[dot_pos+1:]
    second_dot_pos = rest.find('.')
    if second_dot_pos == -1:
      raise AduneoError(f"token {token} is not a JWT, second dot separator not found")

    part_2 = rest[:second_dot_pos]
    rest = rest[second_dot_pos+1:]
    
    third_dot_pos = rest.find('.')
    if third_dot_pos == -1:
      # JWS
      
      b64_payload = part_2
      
      try:
        json_payload = base64.urlsafe_b64decode(b64_payload + '=' * (4 - len(b64_payload) % 4))
      except:
        raise AduneoError(f"token {token} is not a JWT, payload {b64_payload} not Base 64 URL encoded")

      try:
        self.payload = json.loads(json_payload)
      except:
        raise AduneoError(f"token {token} is not a JWT, payload {json_payload} not JSON encoded")
      
      self.b64_signature = rest
      
    else:
      # JWE
      raise AduneoError(f"token {token} is JWE, not supported yet")

    # Chargement de la librairie
    self.library = self.conf.get('preferences/jwt/library', 'jwcrypto')
    if self.library.casefold() == 'jwcrypto':
      if 'jwcrypto' not in jwt_libraries:
        raise AduneoError("jwcrypto configured in preferences/jwt/library but jwcrypto not present in environment. Try pip install jwcrypto to install it")
    else:
      raise AduneoError("JWT library "+self.library+" not supported")
    
    self.token = token
    
    
  def is_signature_valid(self, key: dict, raise_exception:bool=False) -> bool:
    """ Vérifie la signature du jeton
    
    Réponse True/False par défaut, lève une exception en cas d'erreur si raise_exception est à True

    Exemple de clé :
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "T1St-dLTvyWRgxB_676u8krXS-I",
      "x5t": "T1St-dLTvyWRgxB_676u8krXS-I",
      "n": "s2TCRTB0HKEfLBPi3_8CxCbWirz7rlvzcXnp_0j3jrmb_hst0iiHifSBwE0FV1WW79Kyw0AATkLfSLLyllyCuzgoUOgmXd3YMaqB8mQOBIecFQDAHkM1syzi_VwVdJt8H1yI0hOGcOktujDPHidVFtOuoDqAWlCs7kCGwlazK4Sfu_pnfJI4RmU8AvqO0auGcxg24ICbpP01G0PgbvW8uhWSWSSTXmfdIh567JOHsgvFr0m1AUQv7wbeRxgyiHwn29h6g1bwSYJB4I6TMG-cDygvU9lNWFzeYhtqG4Z_cA3khWIMmTq3dVzCsi4iU309-c0FopWacTHouHyMRcpJFQ",
      "e": "AQAB",
      "x5c": [
        "MIIC/TCCAeWgAwIBAgIIUd7j/OIahkYwDQYJKoZIhvcNAQELBQAwLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDAeFw0yMzExMDExNjAzMjdaFw0yODExMDExNjAzMjdaMC0xKzApBgNVBAMTImFjY291bnRzLmFjY2Vzc2NvbnRyb2wud2luZG93cy5uZXQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzZMJFMHQcoR8sE+Lf/wLEJtaKvPuuW/Nxeen/SPeOuZv+Gy3SKIeJ9IHATQVXVZbv0rLDQABOQt9IsvKWXIK7OChQ6CZd3dgxqoHyZA4Eh5wVAMAeQzWzLOL9XBV0m3wfXIjSE4Zw6S26MM8eJ1UW066gOoBaUKzuQIbCVrMrhJ+7+md8kjhGZTwC+o7Rq4ZzGDbggJuk/TUbQ+Bu9by6FZJZJJNeZ90iHnrsk4eyC8WvSbUBRC/vBt5HGDKIfCfb2HqDVvBJgkHgjpMwb5wPKC9T2U1YXN5iG2obhn9wDeSFYgyZOrd1XMKyLiJTfT35zQWilZpxMei4fIxFykkVAgMBAAGjITAfMB0GA1UdDgQWBBRNcCE3HDX+HOJOu/bKfLYoSX3/0jANBgkqhkiG9w0BAQsFAAOCAQEAExns169MDr1dDNELYNK0JDjPUA6GR50jqfc+xa2KOljeXErOdihSvKgDS/vnDN6fjNNZuOMDyr6jjLvRsT0jVWzf/B6v92FrPRa/rv3urGXvW5am3BZyVPipirbiolMTuork95G7y7imftK7117uHcMq3D8f4fxscDiDXgjEEZqjkuzYDGLaVWGJqpv5xE4w+K4o2uDwmEIeIX+rI1MEVucS2vsvraOrjqjHwc3KrzuVRSsOU7YVHyUhku+7oOrB4tYrVbYYgwd6zXnkdouVPqOX9wTkc9iTmbDP+rfkhdadLxU+hmMyMuCJKgkZbWKFES7ce23jfTMbpqoHB4pgtQ=="
      ],
      "issuer": "https://login.microsoftonline.com/b20a2822-5260-4ea7-b000-c17131389b33/v2.0"
    }    
    
    Args:
      key: clé sous la forme d'un dict
      raise_exception: indique si la méthode doit lever une exception en cas d'erreur, utile si on souhaite avoir une explication sur l'échec de vérification, mais dans les faits peu utile
  
    Versions:
      22/12/2023 (mpham) : version initiale
    """
  
    valid = False
  
    try:
      token_key = jwcrypto.jwk.JWK(**key)
    except Exception as error:
      if raise_exception:
        raise AduneoError("Can't verify signature, key is invalid: "+str(error)+" (key is "+str(key)+")")
    
    try:
      jwcrypto.jwt.JWT(jwt=self.token, key=token_key)
      valid = True
    except Exception as error:
      if raise_exception:
        raise AduneoError("Signature verification failed for "+self.token+": "+str(error))
      
    return valid
      
    
    
    
    
