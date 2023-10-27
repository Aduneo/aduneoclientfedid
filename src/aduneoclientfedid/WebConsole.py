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

from .BaseServer import AduneoError
from .BaseServer import BaseHandler
from .Configuration import Configuration
from .Help import Help
from .Template import Template
from .WebConsoleHandler import WebConsoleHandler

import html
import json
import logging

"""
  TODO : je crois qu'on ne peut pas donner la clé publique (drop down list qui ne fonctionne pas)
"""

class WebConsole(BaseHandler):
  
  def display(self):
    buffer = []
    for hdlr in logging.getLogger().handlers:
      if isinstance(hdlr, WebConsoleHandler):
        buffer = hdlr.get_content(self.session_id)
    logs = '' if buffer == [] else "<br>".join([html.escape(line) for line in buffer])+"<br>"
    self.send_template_raw('webconsole.html', logs=logs, log_last_line=str(len(buffer)-1))


  def send_buffer(self):

    log_last_line = self.get_query_string_param('logLastLine')
    if log_last_line:
      log_last_line = int(log_last_line)
    else:
      log_last_line = -1

    buffer = None
    for hdlr in logging.getLogger().handlers:
      if isinstance(hdlr, WebConsoleHandler):
        buffer = hdlr.get_content(self.session_id)

    if buffer:
      out = {"result": "ok", "incr_first_line": log_last_line+1, "log_last_line": len(buffer)-1, "incr": [html.escape(line) for line in buffer[log_last_line+1:]]}
    else:
      out = {"result": "error"}
    self.send_page_raw(json.dumps(out))


  def clear_buffer(self):

    for hdlr in logging.getLogger().handlers:
      if isinstance(hdlr, WebConsoleHandler):
        hdlr.clear_content(self.session_id)

    self.send_page_raw(json.dumps({'result': 'ok'}))
      