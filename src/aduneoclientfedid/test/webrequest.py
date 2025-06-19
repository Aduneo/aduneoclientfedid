import urllib3

from ..WebRequest import WebRequest

#response = WebRequest.get("http://vm0063.maq.aduneo.com:8080", dns_override='192.168.10.65')
response = WebRequest.get("https://www.aduneo.com", verify_certificate=False)
#print(response.data)

def test():

  """
  http = urllib3.PoolManager()
   
  response = http.request('GET', 'https://git.aduneo.com') # make the get request

  print(response.data)
  """


  pool = urllib3.HTTPConnectionPool(
      "192.168.10.63",
      8080,
      #server_hostname="vm0063.maq.aduneo.com",
      #cert_reqs='CERT_NONE',
  )
  response = pool.request(
      "GET",
      "/",
      headers={"Host": "vm0063.maq.aduneo.com"},
      assert_same_host=False
  )

  print(response.data)
  #print(response.json())


  """
  https://urllib3.readthedocs.io/en/1.26.4/reference/urllib3.util.html#urllib3.util.make_headers

  urllib3.util.make_headers(keep_alive=None, accept_encoding=None, user_agent=None, basic_auth=None, proxy_basic_auth=None, disable_cache=None)
  Shortcuts for generating request headers.

  Parameters
  keep_alive – If True, adds ‘connection: keep-alive’ header.

  accept_encoding – Can be a boolean, list, or string. True translates to ‘gzip,deflate’. List will get joined by comma. String will be used as provided.

  user_agent – String representing the user-agent you want, such as “python-urllib3/0.6”

  basic_auth – Colon-separated username:password string for ‘authorization: basic …’ auth header.

  proxy_basic_auth – Colon-separated username:password string for ‘proxy-authorization: basic …’ auth header.

  disable_cache – If True, adds ‘cache-control: no-cache’ header.
  """