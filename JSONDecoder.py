# coding=utf-8
# Burp Extension - JSON decoder
# Copyright : Michal Melewski <michal.melewski@gmail.com>

# Small content-type fix: Nicolas Gregoire
# Force JSON fix: Marcin 'Icewall' Noga

import json
import re

from burp import IBurpExtender
from burp import IMessageEditorTabFactory
from burp import IMessageEditorTab
from burp import IParameter
from burp import IContextMenuFactory

# Java imports
from javax.swing import JMenuItem
from java.util import List, ArrayList

# Menu items
menuItems = {
  False: "Turn JSON active detection on",
  True:  "Turn JSON active detection off"
}

# Global Switch
_forceJSON = False

class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory):
  def registerExtenderCallbacks(self, callbacks):
    self._callbacks = callbacks
    self._helpers = callbacks.getHelpers()

    callbacks.setExtensionName('JSON Decoder')
    callbacks.registerMessageEditorTabFactory(self)
    callbacks.registerContextMenuFactory(self)
    
    return
  
  def createNewInstance(self, controller, editable): 
    return JSONDecoderTab(self, controller, editable)

  def createMenuItems(self, IContextMenuInvocation):
    global _forceJSON
    menuItemList = ArrayList()
    menuItemList.add(JMenuItem(menuItems[_forceJSON], actionPerformed = self.onClick))

    return menuItemList

  def onClick(self, event):
    global _forceJSON
    _forceJSON = not _forceJSON
    
class JSONDecoderTab(IMessageEditorTab):
  def __init__(self, extender, controller, editable):
    self._extender = extender
    self._helpers = extender._helpers
    self._editable = editable
    
    self._txtInput = extender._callbacks.createTextEditor()
    self._txtInput.setEditable(editable)

    self._jsonMagicMark = ['{"', '["', '[{']
    
    return
    
  def getTabCaption(self):
    return "JSON Decoder"
    
  def getUiComponent(self):
    return self._txtInput.getComponent()
    
  def isEnabled(self, content, isRequest):
    global _forceJSON

    if isRequest:
      r = self._helpers.analyzeRequest(content)
    else:
      r = self._helpers.analyzeResponse(content)

    msg = content[r.getBodyOffset():].tostring()
    
    if _forceJSON and len(msg) > 2 and msg[:2] in self._jsonMagicMark:
      print "Forcing JSON parsing and magic mark found: %s"%msg[:2]
      return True
      
    for header in r.getHeaders():
      if header.lower().startswith("content-type:"):
        content_type = header.split(":")[1].lower()
        if content_type.find("application/json") > 0 or content_type.find("text/javascript") > 0:
          return True
        else:
          return False

    return False
    
  def setMessage(self, content, isRequest):
    if content is None:
      self._txtInput.setText(None)
      self._txtInput.setEditable(False)
    else:
      if isRequest:
        r = self._helpers.analyzeRequest(content)
      else:
        r = self._helpers.analyzeResponse(content)
      
      msg = content[r.getBodyOffset():].tostring()
      garbage = msg[:msg.find("{")]
      clean = msg[msg.find("{"):]
      ######
      # 转为中文后后面json.dumps会将其转换回unicode，所有提前dumps并格式化
      clean = json.dumps(json.loads(clean), indent=4)
      m=re.findall(r'(?:\\u[\d\w]{4})+', clean)   # 查找unicode字符
      m = [(i,i.decode('unicode_escape').encode('utf-8')) for i in m]  # 转换成utf-8
      # 替换原字符串
      for n in m:
      	clean = clean.replace(n[0],n[1])
      print clean
      ######	
      try:
        pretty_msg = garbage + clean   # 已经提前格式化过，直接返回
        #pretty_msg = garbage + json.dumps(json.loads(clean), indent=4)
      except:
        print "problem parsing data in setMessage"
        pretty_msg = garbage + clean

      self._txtInput.setText(pretty_msg)
      self._txtInput.setEditable(self._editable)
      
    self._currentMessage = content
    return
    
  def getMessage(self): 
    if self._txtInput.isTextModified():
      try:
        pre_data = self._txtInput.getText()
        garbage = pre_data[:pre_data.find("{")]
        clean = pre_data[pre_data.find("{"):]
        data = garbage + json.dumps(json.loads(clean))
      except:
        data = self._helpers.bytesToString(self._txtInput.getText())
        
      # Reconstruct request/response
      r = self._helpers.analyzeRequest(self._currentMessage)
        
      return self._helpers.buildHttpMessage(r.getHeaders(), self._helpers.stringToBytes(data))
    else:
      return self._currentMessage
    
  def isModified(self):
    return self._txtInput.isTextModified()
    
  def getSelectedData(self):
    return self._txtInput.getSelectedText()
