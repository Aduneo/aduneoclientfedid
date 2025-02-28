"""
Copyright 2023-2025 Aduneo

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
from ..BaseServer import register_web_module, register_api_url
from threading import Lock


"""
  Côté Javascript, la récupération des données est réalisée par les fonctions de requestSender.js

Exemple d'utilisation :

  @register_page_url(url='preparerequest', method='GET', template='page_default.html', continuous=True)
  def prepare_request(self):

    print('HELLO')
    self.add_javascript_include('/javascript/resultTable.js')
    self.add_html('ENCORE HELLO<b>Oh oh</b>')
    self.add_javascript('console.log("LEROY");')
    
    self.add_html('Blah blah')
    self.send_page('Rohhh')

  Le traitement des include est un oeu spécial.
  
    On fait en effet un include dynamique en ajoutant au DOM un élément de type script.
    Cet élément est ajouté instantanément, mais le chargement du fichier se fait par la suite.
    
    Si le code Javascript transmis en même temps que l'include a besoin du fichier, il y a de fortes chances 
      que le fichier n'ait pas encore été intégré.
      
    Lors la récupération des données dans _getHtmlJson, on commence par traiter les include et on s'assure que les fichiers
      correspondant soient bien disponibles.
      
    Pour cela, on s'appuie sur l'événement onload, qui est déclenché justement quand le Javascript du fichier est bien prêt.
      Internet indique que pour que cela fonctionne, l'enchainement suivant doit être respecté :
        - ajout d'un élément script dans le DOM
        - initialisation de l'onload
        - positionnement de src
    Mais dans mes tests, l'ordre n'a pas d'importance
    
    Pour que la fonction _getHtmlJson patiente avant de charger le HTML et le Javascript dans le DOM, on utilise les Promise.
    
    L'ajout du script se fait dans une promesse qui est résolue lorsque l'événement onload est déclenché :
      
      let includeJavascript = (include) => {
        return new Promise((resolve, reject) => {

          let scriptEl = document.createElement("script");
          document.body.appendChild(scriptEl);
          scriptEl.onload = resolve;
          scriptEl.src = include;
          scriptEl.type = "text/javascript";
        });
      }
      
    Il suffit alors de faire un await sur la promesse pour attendre que le code soit pris en compte
      
      for (include of xhttp.response.javascript_include) {
        await includeJavascript(include)
      }

    Et pour que ça fonctionne, la fonction appelée par l'onload de l'XmlHttpRequest doit être déclarée async.
  
    On ne charge un include qu'une seule fois, en les conservant dans javascriptIncludes, 

      for (include of xhttp.response.javascript_include) {
        if (!javascriptIncludes.includes(include)) {
          await includeJavascript(include);
          javascriptIncludes.push(include);
        }
      }
      
    Référence : https://stackoverflow.com/questions/16230886/trying-to-fire-the-onload-event-on-script-tag
"""

class ContinuousPageBuffer(object):
  
  buffer = {}
  buffer_lock = Lock()
  blocs = {}   # bloc insécables
  
  def add_content(cp_id:str, html:str=None, javascript:str=None, javascript_include:str=None, stop:bool=False):
    """ Ajoute au tampon du contenu
  
    Si on est dans un bloc insécable, le contenu est ajouté dans un tampon temporaire (blocs)
    Il sera transféré dans le tampon principal (buffer) à la fin du bloc
  
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      html: code HTML, qui ne doit pas contenir de Javascript (car il ne sera pas exécuté)
      javascript: code Javascript, sans les balises <script>, qui sera exécuté après le HTML
      javascript_include: URL d'include Javascript, qui sera intégrée avant l'exécution du code Javascript
      stop: indique si le polling doit s'arrêter (fin de la page ou fin de section de page)
    
    Versions:
      29/03/2023 (mpham) version initiale
      05/08/2024 (mpham) blocs insécables
      28/02/2025 (mpham) si la page est déjà en redirection, on ne fait rien
    """
    
    with ContinuousPageBuffer.buffer_lock:
    
      if ContinuousPageBuffer.blocs.get(cp_id):
        # on est dans un bloc insécable

        if ContinuousPageBuffer.buffer.get(cp_id, {'action': 'add_content'})['action'] == 'add_content':

          if html:
            ContinuousPageBuffer.blocs[cp_id]['html'] += html

          if javascript:
            ContinuousPageBuffer.blocs[cp_id]['javascript'] += javascript
            
          if javascript_include:
            ContinuousPageBuffer.blocs[cp_id]['javascript_include'].append(javascript_include)
            
          if stop:
            ContinuousPageBuffer.blocs[cp_id]['stop'] = True
        
      else:
        # alimentation normale du tampon principal
    
        if cp_id not in ContinuousPageBuffer.buffer:
          ContinuousPageBuffer.buffer[cp_id] = {'action': 'add_content', 'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}
          
        if ContinuousPageBuffer.buffer[cp_id]['action'] == 'add_content':

          if html:
            ContinuousPageBuffer.buffer[cp_id]['html'] += html

          if javascript:
            ContinuousPageBuffer.buffer[cp_id]['javascript'] += javascript
            
          if javascript_include:
            ContinuousPageBuffer.buffer[cp_id]['javascript_include'].append(javascript_include)
            
          if stop:
            ContinuousPageBuffer.buffer[cp_id]['stop'] = True


  def redirect(cp_id:str, url:str):
    """ Demande au navigateur de réaliser une redirection
    
    Ignore le contenu déjà envoyé
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      url: URL de redirection

    Versions:
      28/02/2025 (mpham) version initiale
    """
    with ContinuousPageBuffer.buffer_lock:
      ContinuousPageBuffer.buffer[cp_id] = {'action': 'redirect', 'url': url}
    
  
  def get_buffer(cp_id:str) -> dict:
    """ Retourne le buffer d'un navigateur
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      
    Returns:
      Un dict avec les éléments suivants :
        - html : code HTML
        - javascript : code Javascript, avec les balises <script>
        - javascript_include : tableau d'URL de fichiers Javascript à inclure
    
    S'il y a des include, on commence par les envoyer seules, pour donner au navigateur le temps de les charger
    
    Versions:
      29/03/2023 (mpham) version initiale
    """

    buffer = {'action': 'add_content', 'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}

    with ContinuousPageBuffer.buffer_lock:
      if cp_id in ContinuousPageBuffer.buffer:
        #print('---- cp_id trouvé ----')
        buffer = ContinuousPageBuffer.buffer[cp_id]
        ContinuousPageBuffer.buffer.pop(cp_id)
        
    return buffer


  def start_continuous_page_block(cp_id):
    """ Démarrage un bloc de contenu insécable
    
    Le bloc doit être envoyé dans son ensemble, sinon le navigateur va ajouter des éléments parasites.
    
    C'est par exemple le cas si on récupère du tampon un tableau (table) en plusieurs fois.
    A chaque récupération, le navigateur ferme le tableau.
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      
    Versions:
        05/08/2024 (mpham) version initiale
    """
    with ContinuousPageBuffer.buffer_lock:
      if cp_id not in ContinuousPageBuffer.blocs:
        ContinuousPageBuffer.blocs[cp_id] = {'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}

  
  def end_continuous_page_block(cp_id):
    """ Ferme un bloc de contenu insécable
    
    Le bloc est transféré vers le tampon principal
    
    Args:
      cp_id: identifiant de la page du navigateur devant recevoir le contenu
      
    Versions:
      05/08/2024 (mpham) version initiale
      28/02/2025 (mpham) ajout de l'action dans le buffer
    """
    with ContinuousPageBuffer.buffer_lock:
      
      bloc = ContinuousPageBuffer.blocs.get(cp_id)
      if bloc:
        del ContinuousPageBuffer.blocs[cp_id]

        if cp_id not in ContinuousPageBuffer.buffer:
          ContinuousPageBuffer.buffer[cp_id] = {'action': 'add_content', 'html': '', 'javascript': '', 'javascript_include': [], 'stop': False}
          
        ContinuousPageBuffer.buffer[cp_id]['html'] += bloc['html']
        ContinuousPageBuffer.buffer[cp_id]['javascript'] += bloc['javascript']
        ContinuousPageBuffer.buffer[cp_id]['javascript_include'].extend(bloc['javascript_include'])
        if bloc['stop']:
          ContinuousPageBuffer.buffer[cp_id]['stop'] = True
  


@register_web_module('/continuouspage')
class ContinuousPage(BaseHandler):

  @register_api_url(method='GET')
  def poll(self):
  
    cp_id = self.get_query_string_param('cp_id')
    
    buffer = ContinuousPageBuffer.get_buffer(cp_id)
    #print(buffer)
    
    self.send_json(buffer)

