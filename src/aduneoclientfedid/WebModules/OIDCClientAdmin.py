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

from ..BaseServer import AduneoError
from ..BaseServer import BaseHandler
from ..BaseServer import register_web_module, register_url
from ..Configuration import Configuration
from ..Help import Help
import html
import time

"""
  TODO : je crois qu'on ne peut pas donner la clé publique (drop down list qui ne fonctionne pas)
"""

@register_web_module('/client/oidc/admin')
class OIDCClientAdmin(BaseHandler):
  
  @register_url(url='modifyclient', method='GET')
  def display(self):
    
    """
    Ajout/modification d'un client OIDC
    
    mpham 12/02/2021 - 27/02/2021 - 28/12/2021 - 13/04/2021
    mpham 09/12/2022 - ajout de token_endpoint_auth_method
    mpham 22/02/2023 - désactivation des IdP de préférence en attendant une industrialisation et traduction en anglais des titres
    mpham 22/02/2023 - suppression des références à fetch_userinfo puisque l'appel à userinfo est désormais manuel
    """
    
    rp = {}
    rp_id = self.get_query_string_param('id', '')
    if rp_id != '':
      rp = self.conf['oidc_clients'][rp_id]

    redirect_uri = rp.get('redirect_uri', '')
    
    self.add_content('<form name="rp" action="" method="post">')
    self.add_content('<input name="rp_id" value="'+html.escape(rp_id)+'" type="hidden" />')
    """
    self.add_content('<h1>Préférences')
    #Bouton deroulant
    self.add_content('''
      <select onChange="includeHtml(this.value)">
        <option value="any">Any</option>
        <option value="okta">Okta</option>
        <option value="keycloak">Keycloak</option>
        <option value="azuread">Azure AD</option>
      </select>
      ''')
    self.add_content('</h1>')
    """

    self.add_content('<h2>General configuration</h2>')

    self.add_content('<table id="unTab" class="fixed">')
    self.add_content('<tr><td><span class="celltxt">Name</span><span class="cellimg"><img onclick="help(this, \'name\')" src="/images/help.png"></span></td><td><input name="name" value="'+html.escape(rp.get('name', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td><span class="celltxt">Redirect URI</span><span class="cellimg"><img onclick="help(this, \'redirect_uri\')" src="/images/help.png"></span></td><td><input name="redirect_uri" id="redirect_uri" value="'+html.escape(redirect_uri)+'" class="intable" type="text"></td></tr>')
    
    # méthode de configuration des endpoint
    self.add_content('<tr><td>'+self.row_label('Endpoint configuration', 'endpoint_configuration')+'</td><td><select name="endpoint_configuration" class="intable" onchange="changeEndpointConfiguration()">')
    for value in ('Discovery URI', 'Local configuration'):
      selected = ''
      if value.casefold() == rp.get('endpoint_configuration', 'Discovery URI').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</td></tr>')

    self.add_content('</table>')
    #Première étape de l'assistance
    self.add_content("""<div id="un" class="fixed etapes" hidden>
      Ces champs sont arbitraires, mettez le nom que vous souhaitez ainsi que la méthode qui vous semble la plus pratique pour récupérez les informations du fournisseur d\'identité.
      <p id="includeUn"></p> 
      <button class="button" type="button" style="padding: 5px 10px !important;" onclick="showHelp(\'deux\');">Continuer</button></div>""")
    self.add_content('<h2>Parameters obtained from the OP</h2>')
    self.add_content('<table id="deuxTab" class="fixed">')

    # configuration des endpoint par discovery uri
    visible = (rp.get('endpoint_configuration', 'Discovery URI').casefold() == 'discovery uri')
    visible_style = 'none'
    if visible:
      visible_style = 'table-row'
    self.add_content('<tr id="discovery_uri" style="display: '+visible_style+';"><td>'+self.row_label('Discovery URI', 'discovery_uri')+'</td><td><input name="discovery_uri" value="'+rp.get('discovery_uri', '')+'" class="intable" type="text"></td></tr>')
    
    # configuration des endpoint dans le fichier local
    visible = (rp.get('endpoint_configuration', 'Discovery URI').casefold() == 'local configuration')
    visible_style = 'none'
    if visible:
      visible_style = 'table-row'
    self.add_content('<tr id="issuer" style="display: '+visible_style+';"><td>'+self.row_label('Issuer', 'issuer')+'</td><td><input name="issuer" value="'+html.escape(rp.get('issuer', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr id="authorization_endpoint" style="display: '+visible_style+';"><td>'+self.row_label('Authorization endpoint', 'authorization_endpoint')+'</td><td><input name="authorization_endpoint" value="'+html.escape(rp.get('authorization_endpoint', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr id="token_endpoint" style="display: '+visible_style+';"><td>'+self.row_label('Token endpoint', 'token_endpoint')+'</td><td><input name="token_endpoint" value="'+html.escape(rp.get('token_endpoint', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr id="userinfo_endpoint" style="display: '+visible_style+';"><td>'+self.row_label('Userinfo endpoint', 'userinfo_endpoint')+'</td><td><input name="userinfo_endpoint" value="'+html.escape(rp.get('userinfo_endpoint', ''))+'" class="intable" type="text"></td></tr>')

    # configuration de la clé de vérification de signature
    self.add_content('<tr id="signature_key_configuration" style="display: '+visible_style+';"><td>'+self.row_label('Signature key configuration', 'signature_key_configuration')+'</td><td><select name="signature_key_configuration" class="intable" onchange="changeEndpointConfiguration()">')
    for value in ('JWKS URI', 'Local configuration'):
      selected = ''
      if value.casefold() == rp.get('signature_key_configuration', 'JWKS URI').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</td></tr>')
    
    # clé de signature récupérée par JWKS
    key_visible = (rp.get('signature_key_configuration', 'JWKS URI').casefold() == 'jwks uri')
    key_visible_style = 'none'
    if key_visible:
      key_visible_style = 'table-row'
    if not visible:
      key_visible_style = 'none'
    self.add_content('<tr id="jwks_uri" style="display: '+key_visible_style+';"><td>'+self.row_label('JWKS URI', 'jwks_uri')+'</td><td><input name="jwks_uri" value="'+html.escape(rp.get('jwks_uri', ''))+'" class="intable" type="text"></td></tr>')
    
    # clé de signature dans le fichier local
    key_visible = (rp.get('signature_key_configuration', 'JWKS URI').casefold() == 'local configuration')
    key_visible_style = 'none'
    if key_visible:
      key_visible_style = 'table-row'
    if not visible:
      key_visible_style = 'none'
    self.add_content('<tr id="signature_key" style="display: '+key_visible_style+';"><td>'+self.row_label('Signature Key', 'signature_key')+'</td><td><input name="signature_key" value="'+html.escape(rp.get('signature_key', ''))+'" class="intable" type="text"></td></tr>')
    
    # configuration de la cinématique
    self.add_content('<tr><td>'+self.row_label('Client ID', 'client_id')+'</td><td><input name="client_id" value="'+html.escape(rp.get('client_id', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Client secret', 'client_secret')+'</td><td><input name="client_secret!" value="" class="intable" type="password"></td></tr>')

    self.add_content('</table>')
    # deuxième étape de l'assistance
    self.add_content("""<div id="deux" class="fixed etapes"  hidden> Il s\'agit ici des champs spécifiques à votre IdP. <br>- choisissez en premier l\'url qui va permettre au client de récupérer les metadonnées de votre IdP souvent cette url est celle définie dans la RFC 5785 qui est de la forme /.well-known/openid-configuration <br>- Vous trouverez les deux derniers champs dans la page de configuration de votre application sur votre IdP. <p id="includeDeux"></p><button class="button" type="button" style="padding: 5px 10px !important;" onclick="showHelp(\'trois\');">Continuer</button>
      </p></div>""")

    self.add_content('<h2>Default OIDC request parameters</h2>')
    self.add_content('<table id="troisTab" class="fixed">')

    self.add_content('<tr><td>'+self.row_label('Scope', 'scope')+'</td><td><input name="scope" value="'+html.escape(rp.get('scope', 'openid profile'))+'" class="intable" type="text"></td></tr>')
    self.add_content('<tr><td>'+self.row_label('Response type', 'response_type')+'</td><td><select name="response_type" class="intable">')
    for value in ['code']:
      selected = ''
      if value == rp.get('response_type', ''):
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</select></td></tr>')
    
    self.add_content('<tr><td>'+self.row_label('Token endpoint auth method', 'token_endpoint_auth_method')+'</td><td><select name="token_endpoint_auth_method" class="intable" >')
    for value in ('Basic', 'POST'):
      selected = ''
      if value.casefold() == rp.get('token_endpoint_auth_method', 'POST').casefold():
        selected = ' selected'
      self.add_content('<option value="'+value+'"'+selected+'>'+html.escape(value)+'</value>')
    self.add_content('</td></tr>')
    
    self.add_content('</table>')
    #Troisième étape de l'assistance
    self.add_content("""<div id="trois" class="etapes fixed"  hidden> Ces champs sont les paramètres par défaut pour les champs obligatoires que vous voulez appliquer à vos requêtes. <p id="includeTrois"></p><button class="button" type="button" style="padding: 5px 10px !important;" onclick="showHelp(\'quatre\');">Continuer</button>
    </p></div>""")

    self.add_content('<h2>Logout configuration (optional)</h2>')
    self.add_content('<h3>Logout information provided by the OP</h3>')
    self.add_content('<table class="fixed">')
    # configuration des endpoint dans le fichier local
    visible = (rp.get('endpoint_configuration', 'Discovery URI').casefold() == 'local configuration')
    visible_style = 'none'
    if visible:
      visible_style = 'table-row'
    self.add_content('<tr id="end_session_endpoint" style="display: '+visible_style+';"><td>'+self.row_label('Logout endpoint', 'end_session_endpoint')+'</td><td><input name="end_session_endpoint" value="'+html.escape(rp.get('end_session_endpoint', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('</table>')
    
    self.add_content('<h3>Logout information provided by ClientFedId, used to configure the OP</h3>')
    self.add_content('<table class="fixed">')
    self.add_content('<tr><td><span class="celltxt">Post logout redirect URI</span><span class="cellimg"><img onclick="help(this, \'post_logout_redirect_uri\')" src="/images/help.png"></span></td><td><input name="post_logout_redirect_uri" id="post_logout_redirect_uri" value="'+html.escape(rp.get('post_logout_redirect_uri', ''))+'" class="intable" type="text"></td></tr>')
    self.add_content('</table>')

    
    self.add_content('<h2>Options</h2>')
    self.add_content('<table id="quatreTab" class="fixed">')

    checked = ''
    if Configuration.is_on(rp.get('verify_certificates', 'on')):
      checked = ' checked'
    self.add_content('<tr><td>'+self.row_label('Verify certificates', 'verify_certificates')+'</td><td><input name="verify_certificates" type="checkbox"'+checked+'></td></tr>')
    self.add_content('</table>')
    # quatrimème étape de l'assistance
    self.add_content("""<div id="quatre" class="etapes fixed"  hidden> Options de comportement du client <p id="includeQuatre"></p><button class="button" type="button" style="padding: 5px 10px !important;" onclick="showHelp(\'zero\');">Continuer</button>
    </p></div>""")
    
    self.add_content('<button type="submit" class="button">Save</button>')
    #self.add_content('<button type="button" class="button" onclick="showHelp(\'un\');">Assistance</button>')
    #self.add_content('<a href="/oidc/client/modifyclient/guide?id="'+rp_id+'"><button type="button" class="button">Guide</button></a>')

    self.add_content('</form>')

    self.add_content("""
      <script>
      
      window.addEventListener('load', (event) => {
        if (document.getElementById('redirect_uri').value == '') {
          document.getElementById('redirect_uri').value = window.location.origin + '/client/oidc/login/callback';
        }
        if (document.getElementById('post_logout_redirect_uri').value == '') {
          document.getElementById('post_logout_redirect_uri').value = window.location.origin + '/client/oidc/logout/callback';
        }
      });
      
      function changeEndpointConfiguration() {
        if (document.rp.endpoint_configuration.value == 'Discovery URI') {
          document.getElementById('discovery_uri').style.display = 'table-row';
          ['issuer', 'authorization_endpoint', 'end_session_endpoint', 'token_endpoint', 'userinfo_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key'].forEach(function(item, index) {
            document.getElementById(item).style.display = 'none';
          });
        } else {
          document.getElementById('discovery_uri').style.display = 'none';
          ['issuer', 'authorization_endpoint', 'token_endpoint', 'end_session_endpoint', 'userinfo_endpoint', 'signature_key_configuration'].forEach(function(item, index) {
            document.getElementById(item).style.display = 'table-row';
          });
          if (document.rp.signature_key_configuration.value == 'JWKS URI') {
            document.getElementById('jwks_uri').style.display = 'table-row';
            document.getElementById('signature_key').style.display = 'none';
          } else {
            document.getElementById('jwks_uri').style.display = 'none';
            document.getElementById('signature_key').style.display = 'table-row';
          }
        }
      }
      </script>
    """)

    self.add_content(Help.help_window_definition())
    
    self.send_page()


  @register_url(url='modifyclient', method='POST')
  def modify(self):
  
    """
    Crée ou modifie un IdP dans la configuration
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    mpham 24/12/2021 - ajout de redirect_uri
    mpham 09/12/2022 - ajout de token_endpoint_auth_method
    mpham 22/02/2023 - suppression des références à fetch_userinfo puisque l'appel à userinfo est désormais manuel
    """
    
    rp_id = self.post_form['rp_id']
    if rp_id == '':
      rp_id = self._generate_rpid(self.post_form['name'], self.conf['oidc_clients'].keys())
      self.conf['oidc_clients'][rp_id] = {}
    
    rp = self.conf['oidc_clients'][rp_id]
    
    if self.post_form['name'] == '':
      self.post_form['name'] = rp_id
    
    for item in ['name', 'redirect_uri', 'endpoint_configuration', 'discovery_uri', 'issuer', 'authorization_endpoint', 'token_endpoint', 
    'end_session_endpoint', 'userinfo_endpoint', 'signature_key_configuration', 'jwks_uri', 'signature_key', 
    'client_id', 'scope', 'response_type', 'token_endpoint_auth_method', 'post_logout_redirect_uri']:
      if self.post_form[item] == '':
        rp.pop(item, None)
      else:
        rp[item] = self.post_form[item]
      
    for secret in ['client_secret!']:
      if self.post_form[secret] != '':
        rp[secret] = self.post_form[secret]
        
    for item in ['verify_certificates']:
      if item in self.post_form:
        rp[item] = 'on'
      else:
        rp[item] = 'off'

    Configuration.write_configuration(self.conf)
    
    self.send_redirection('/')


  @register_url(url='removeclient', method='GET')
  def remove(self):
  
    """
    Supprime un client OpenID Connect
    
    mpham 28/12/2021
    """

    rp_id = self.get_query_string_param('id')
    if rp_id is not None:
      self.conf['oidc_clients'].pop(rp_id, None)
      Configuration.write_configuration(self.conf)
      
    self.send_redirection('/')


  def _generate_rpid(self, name, existing_names):
    
    """
    Génère un identifiant à partir d'un nom
    en ne retenant que les lettres et les chiffres
    et en vérifiant que l'identifiant n'existe pas déjà
    
    S'il existe, ajoute un suffixe numérique
    
    mpham 28/02/2021
    """
    
    base = name
    ok = False
    rank = 0
    
    while not ok:
      id = ''.join(c for c in base.casefold() if c.isalnum())
      if id == '':
        id = 'oidc_rp'
      if rank > 0:
        id = id+str(rank)
      
      if id in existing_names:
        rank = rank+1
      else:
        ok = True
        
    return id
