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

import time

from logging import StreamHandler
from threading import Lock, Thread

class WebConsoleHandler(StreamHandler):

  TIMEOUT = 20*60

  class BackgroundTask(Thread):
    """Expiration des buffers liés aux sessions
    
    mpham 01/06/2022
    """

    def __init__(self, handler):
      self.handler = handler
      Thread.__init__(self, daemon=True)

    def run(self):
      while True:
        for session_id in list(self.handler.buffers.keys()):
          if int(time.time()) > self.handler.buffers[session_id]['expiry']:
            del self.handler.buffers[session_id]
        time.sleep(2)


  def __init__(self):
    StreamHandler.__init__(self)
    #self.WEB_CONSOLE_BUFFER = []
    self.buffers = {}   # clé session_id, 
    #self.lock = Lock()
    
    self.thread = WebConsoleHandler.BackgroundTask(self)
    self.thread.start()

    
  def emit(self, record):
    if 'sessionid' in record.__dict__:
      #self.lock.acquire()
      session_id = record.__dict__['sessionid']
      if session_id not in self.buffers:
        self.buffers[session_id] = {'expiry': 0, 'log': []}
      self.buffers[session_id]['log'].append(self.format(record))
      self.buffers[session_id]['expiry'] = int(time.time()) + WebConsoleHandler.TIMEOUT
      #self.lock.release()
    
    #self.WEB_CONSOLE_BUFFER.append(self.format(record))
    
    
  def get_content(self, session_id) -> []:
  
    log = []
  
    if session_id in self.buffers:
      #self.lock.acquire()
      log = self.buffers[session_id]['log'].copy()
      #self.buffers[session_id]['log'] = []
      self.buffers[session_id]['expiry'] = int(time.time()) + WebConsoleHandler.TIMEOUT
      #self.lock.release()
      
      #buffer = self.WEB_CONSOLE_BUFFER.copy()
      #self.WEB_CONSOLE_BUFFER = []
    
    return log


  def clear_content(self, session_id):
  
    if session_id in self.buffers:
      self.buffers[session_id]['log'] = []
      self.buffers[session_id]['expiry'] = int(time.time()) + WebConsoleHandler.TIMEOUT
