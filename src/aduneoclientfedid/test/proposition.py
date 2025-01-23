from ..Proposition import Proposition


class proposition_test():
  
  def test():
    
    expression = "@a = '2' and @b = '3' or @a = '12' and @b = '13' or (@a = '5' or @a = '7') @hello"
    #expression = "@a = '2'"
    values = {
      'a': '12',
      'b': '13',
    }
    
    proposition = Proposition(expression)
    #print(proposition.eval(values))
    print(proposition.transpose_javascript(lambda var: var+'s'))
    
