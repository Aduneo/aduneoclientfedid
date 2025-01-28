from ..BasicXML import BasicXML


class basicxml_test():
  
  def test():
  
    content = """<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
    <cas:authenticationSuccess>
        <cas:user>monet</cas:user>
        <cas:attributes>
            <cas:mail>claude.monet@aduneo.com</cas:mail>
            <cas:givenName>Claude</cas:givenName>
            <cas:sn>Monet</cas:sn>
            <cas:cn>Claude Monet</cas:cn>
        </cas:attributes>
    </cas:authenticationSuccess>
</cas:serviceResponse>
"""

    parsed = BasicXML.parse(content)
    print(parsed)
    print(parsed.attributes['cas:serviceResponse'])
