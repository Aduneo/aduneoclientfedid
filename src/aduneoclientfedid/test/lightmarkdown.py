from ..Help import Help


class lightmarkdown_test():
  
  def test():
  
    content = """Hello
Comment<br>
allez-vous ?
- ligne de liste
- et encore une
Et maintenant
1. des numéros
1. et encore !
3 et plus rien.

"""
    
    print(Help.convert_from_light_markdown(content))
    
    print(Help._convert_text_from_light_markdown('2\*2=4 et **gras** ceci *cela*'))
