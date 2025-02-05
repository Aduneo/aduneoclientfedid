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
from .BaseServer import AduneoError


class BasicXML(dict):
  """ Parsing très limité de XML
  
  pour les réponses CAS
  
  Versions:
    26/01/2025 (mpham) version initiale
  """

  def __init__(self):
    """ Constructeur
    
    Versions:
      26/01/2025 (mpham) version initiale
    """
    self.attributes = {}  # clé : clé du dict, valeur : dict avec les attributs de l'élément correspondant à la clé


  def add_element(self, element_name, attributes, content):
    """ Ajoute un sous-élément à un élément

    Pour cela :
      - ajoute une clé au dict, avec le contenu en valeur
      - ajoute les attributs au dictionnaire des attributs
    
    Args:
      start_tag: chaîne avec le nom de l'élément à ajouter suivi de ses attributs, par exemple : category format="normal"
      content: contenu de l'élément, None (élément vide), un text ou un BasicXML
      
    Versions:
      26/01/2025 (mpham) version initiale
    """
    
    self[element_name] = content
    self.attributes[element_name] = attributes
    

  def parse(text:str):
    """ parseur XML simplifié
    
    Prend une chaîne de la forme <balise_principale><balise1>...</balise1><balise2>...</balise2></balise_principale>
      pour en faire un dict {"balise_principale": {"balise1": ..., <"balise2": ...}}
    
    Args:
      text: chaîne XML de syntaxe <balise1>...</balise1><balise2>...</balise2>
      
    Returns:
      objet BasicXML
      
    Versions:
      26/01/2025 (mpham) version initiale
    """
    
    class XMLParser():
      
      def __init__(self, text:str):
        self.text = text
        self.current_pos = 0
        
        
      def parse(self) -> BasicXML:
        """ Parse XML
        
        Prend une chaîne de la forme <balise_principale><balise1>...</balise1><balise2>...</balise2></balise_principale>
          pour en faire un dict {"balise_principale": {"balise1": ..., <"balise2": ...}}
        
        Args:
          text: chaîne XML de syntaxe <balise1>...</balise1><balise2>...</balise2>
          
        Versions:
          26/01/2025 (mpham) version initiale
        """

        self.current_pos = 0

        # on cherche la balise principale
        self.skip_spaces()

        if self.text[self.current_pos] != '<':
          raise AduneoError(f"XML string must begin with a tag")
        opening_bracket_pos = self.current_pos
        if self.text[self.current_pos+1] == '/':
          raise AduneoError(f"unexpected closing tag at beginning of XML string")

        closing_bracket_pos = self.text.find('>', self.current_pos)
        if closing_bracket_pos == -1:
          raise AduneoError("no closing bracket at position {opening_bracket_pos} in {self.text}")

        root_start_tag = self.text[opening_bracket_pos+1:closing_bracket_pos]
        root_tag = BasicXML()
        self.move_current_pos_to(closing_bracket_pos+1)
        (element_name, attributes) = XMLParser.parse_start_tag(root_start_tag)
        root_tag.add_element(element_name, attributes, self.parse_tag(element_name))
        
        return root_tag


      def parse_start_tag(start_tag):
        """ Analyse la balise de début d'un élément en nom et attributs

        Args:
          start_tag: chaîne avec le nom de l'élément à ajouter suivi de ses attributs, par exemple : category format="normal"

        Returns:
          (element_name, attributes) où attributes est un dict
          
        Versions:
          26/01/2025 (mpham) version initiale
        """

        element_name = None
        attributes = {}

        space_pos = start_tag.find(' ')
        if space_pos == -1:
          element_name = start_tag
        else:
          element_name = start_tag[:space_pos]
          
          current_pos = space_pos
          attribute_loop = True
          while attribute_loop:
            
            space_loop = True
            while space_loop:
              if current_pos >= len(start_tag):
                space_loop = False
                attribute_loop = False
              elif start_tag[current_pos] == ' ' or start_tag[current_pos] == '\r' or start_tag[current_pos] == '\n':
                current_pos += 1
              else:
                space_loop = False

            if attribute_loop:
              equals_pos = start_tag.find('=', current_pos)
              if equals_pos == -1:
                raise AduneoError(f"expecting opening bracket at position {self.current_pos} ({self.text[self.current_pos:self.current_pos+10]}) in {self.text}")
              attribute_name = start_tag[current_pos:equals_pos].strip()
              current_pos = equals_pos
              
              opening_quote_pos = start_tag.find('"', current_pos)
              if opening_quote_pos == -1:
                raise AduneoError(f"expecting opening quote at position {self.current_pos} ({self.text[self.current_pos:self.current_pos+10]}) in {self.text}")
              current_pos = opening_quote_pos+1
              
              closing_quote_pos = start_tag.find('"', current_pos)
              if closing_quote_pos == -1:
                raise AduneoError(f"expecting closing quote at position {self.current_pos} ({self.text[self.current_pos:self.current_pos+10]}) in {self.text}")
              current_pos = closing_quote_pos+1

              value = start_tag[opening_quote_pos+1:closing_quote_pos]
              attributes[attribute_name] = value
          

        return (element_name, attributes)


      def parse_tag(self, element_name):
        """ Parse le contenu d'un élément XML
        
        Analyse le contenu d'un tag :
          - self.current_pos est positionné juste après la balise ouvrante
          - l'analyse s'arrête quand la balise fermante est trouvée
          - un objet BasicXML est créé si le contenu est composé de balises
        
        Args:
          element_name: nom de l'élement
          
        Versions:
          26/01/2025 (mpham) version initiale
        """
        
        content = None
        
        # On commence par déterminer ce qu'il y a dans la balise : du contenu, des balises ou rien
        if self.text[self.current_pos-2] == '/':
          # élément vide (<balise/>)
          content = None
        else:
        
          start_pos = self.current_pos
          self.skip_spaces()
          if self.text[self.current_pos] == '<':
            self.move_current_pos_to(self.current_pos+1)
            if self.text[self.current_pos] == '/':
              # contenu vide
              closing_bracket_pos = self.text.find('>', self.current_pos)
              if closing_bracket_pos == -1:
                raise AduneoError(f"matching closing bracket not found at position {self.current_pos-1} in {self.text}")
              closing_tag_name = self.text[self.current_pos:closing_bracket_pos]
              if element_name != closing_tag_name:
                raise AduneoError(f"end tag {closing_tag_name} does not match start tag {element_name} at position {self.current_pos-1} in {self.text}")
              content = None
                
            else:
              # balise ouvrante
              content = BasicXML()
              end = False
              while not end:
                
                opening_bracket_pos = self.current_pos-1
                if self.text[self.current_pos+1] == '/':
                  raise AduneoError(f"unexpected closing tag at beginning of XML string")

                closing_bracket_pos = self.text.find('>', self.current_pos)
                if closing_bracket_pos == -1:
                  raise AduneoError("no closing bracket at position {opening_bracket_pos} in {self.text}")

                start_tag = self.text[opening_bracket_pos+1:closing_bracket_pos]
                self.move_current_pos_to(closing_bracket_pos+1)
                (sub_element_name, attributes) = XMLParser.parse_start_tag(start_tag)
                content.add_element(sub_element_name, attributes, self.parse_tag(sub_element_name))

                self.skip_spaces()
                if self.text[self.current_pos] != '<':
                  raise AduneoError(f"expecting opening bracket at position {self.current_pos} ({self.text[self.current_pos:self.current_pos+10]}) in {self.text}")
                  
                self.move_current_pos_to(self.current_pos+1)
                if self.text[self.current_pos] == '/':
                  # fin de l'élément
                  closing_bracket_pos = self.text.find('>', self.current_pos)
                  if closing_bracket_pos == -1:
                    raise AduneoError(f"matching closing bracket not found at position {self.current_pos-1} in {self.text}")
                  closing_tag_name = self.text[self.current_pos+1:closing_bracket_pos]
                  if element_name != closing_tag_name:
                    raise AduneoError(f"end tag {closing_tag_name} does not match start tag {element_name} at position {self.current_pos-1} ({self.text[self.current_pos-1:self.current_pos+10]}) in {self.text}")
                  end = True
                  self.move_current_pos_to(closing_bracket_pos+1)
                
          else:
            # contenu texte
            opening_bracket_pos = self.text.find('<', self.current_pos)
            self.move_current_pos_to(opening_bracket_pos+1)
            if self.text[self.current_pos] != '/':
              raise AduneoError(f"expecting closing tag at position {self.current_pos-1} ({self.text[self.current_pos-1:self.current_pos+10]}) in {self.text}")

            closing_bracket_pos = self.text.find('>', self.current_pos)
            if closing_bracket_pos == -1:
              raise AduneoError(f"matching closing bracket not found at position {self.current_pos-1} ({self.text[self.current_pos-1:self.current_pos+10]}) in {self.text}")
            closing_tag_name = self.text[opening_bracket_pos+2:closing_bracket_pos]
            if element_name != closing_tag_name:
              raise AduneoError(f"end tag {closing_tag_name} does not match start tag {element_name} at position {self.current_pos-1} in {self.text}")
            
            content = self.text[start_pos:opening_bracket_pos]
            self.move_current_pos_to(closing_bracket_pos+1)
        
        return content
        

      def skip_spaces(self):
        """ Saute espaces et retours à la ligne
        
        Versions:
          26/01/2025 (mpham) version initiale
        """
        
        while self.text[self.current_pos] == ' ' or self.text[self.current_pos] == '\r' or self.text[self.current_pos] == '\n':
          self.move_current_pos_to(self.current_pos+1)


      def move_current_pos_to(self, position:int):
        """ Déplace le curseur d'analyse self.current_pos, en vérifiant qu'on ne sort pas de la chaîne
        
        Versions:
          26/01/2025 (mpham) version initiale
        """
        if position > len(self.text):
          raise AduneoError(f"unexpected end of XML string")
        self.current_pos = position


    # début du code de la méthode BasicXML.parse()    
    parser = XMLParser(text)
    return parser.parse()

    
    

