from ..Configuration import conf_dict, Configuration

class configuration_test():
  
  def test():
    print("Test")
    
    conf = conf_dict()
    conf['preferences'] = conf_dict()
    conf['preferences']['hello'] = 'world'
    
    d = {'guitare': {}}
    d['guitare'] = {'électrique': {}, 'acoustique': {}, 'classique': {}}
    d['guitare']['électrique'] = {'solid': {}, 'hollow': {}, 'semi-hollow': {}}
    d['guitare']['électrique']['solid'] = ['normal', 'offset']
    
    c = conf_dict.copy(d)
    print('---')
    print(c['guitare/électrique/solid'])
    print(c['guitare']['électrique/solid'])
    print('---')
    
    
    print(conf.get('preferences/hello'))
    
    print(conf.get('preferences/notfound', 'Not found'))
    
    print(conf['preferences/hello'])
    
    try:
      print(conf['preferences/notfound'])
    except:
      print('Not found')
    
    print('---')
    
    conf = Configuration.read_configuration('clientfedid.cnf')
    print(conf['preferences']['logging']['handler'])
    print(conf['preferences/logging/handler'])
    print(conf['/preferences']['logging/handler'])
    
    print('should be true: ', conf.is_on('server/ssl'))
    print('should be false: ', conf.is_on('server/ssl1'))
    print('should be true: ', conf.is_on('server/ssl1', True))
    
    conf = conf_dict()
    conf['server'] = {'ssl': True}
    print('should be true: ', conf.is_on('server/ssl'))
