import json
import logging
import sys

class JSONLoad():
  '''
  Purpose: Load & Parse JSON config for ARMulator
  '''

  def __init__(self, config_file):
    self.f_name = config_file
    self.json_data = self.read_config()

    self.code_path = ""
    self.load_address = ""

    self.parse_config() # Populates the JSON variables above.

  def read_config(self):
    '''
    Parameter: N/A 
    Purpose: Read JSON file and return JSON data.
    Return: Populates self.json_data.
    '''
    try:
      with open(self.f_name) as fin:
        json_data = json.load(fin)
      return json_data
    except FileNotFoundError as f_io:
      logging.error("[!] Error, I could not find %s" % str(self.f_name))
      sys.exit(1)
      
  def parse_config(self):
    '''
    Parameter: N/A
    Purpose: Parse out all desired JSON config file items.
    '''
    try:
      ## GENERAL ##
      # self.code_path = self.json_data["code_path"]
      self.load_address = int(self.json_data["load_address"],16)
      self.arch = self.json_data["arch"]

      ## RAM CONFIG ##
      self.ram_dump = self.json_data["ram"]["ram_dump"]
      self.ram_address = int(self.json_data["ram"]["ram_address"],16)

      ## REGISTER CONFIG ##
      self.reg_arm_r0 =  int(self.json_data["registers"]["r0"],16)
      self.reg_arm_r1 =  int(self.json_data["registers"]["r1"],16)
      self.reg_arm_r2 =  int(self.json_data["registers"]["r2"],16)
      self.reg_arm_r3 =  int(self.json_data["registers"]["r3"],16)
      self.reg_arm_r4 =  int(self.json_data["registers"]["r4"],16)
      self.reg_arm_r5 =  int(self.json_data["registers"]["r5"],16)
      self.reg_arm_r6 =  int(self.json_data["registers"]["r6"],16)
      self.reg_arm_r7 =  int(self.json_data["registers"]["r7"],16)
      self.reg_arm_r8 =  int(self.json_data["registers"]["r8"],16)
      self.reg_arm_r9 =  int(self.json_data["registers"]["r9"],16)
      self.reg_arm_r10 = int(self.json_data["registers"]["r10"],16)
      self.reg_arm_r11 = int(self.json_data["registers"]["r11"],16)
      self.reg_arm_r12 = int(self.json_data["registers"]["r12"],16)
      self.reg_arm_lr =  int(self.json_data["registers"]["lr"],16)
      self.reg_arm_sp =  int(self.json_data["registers"]["sp"],16)
      self.reg_arm_pc =  int(self.json_data["registers"]["pc"],16)

    except KeyError as k_err:
      logging.error("[!] Config entry missing: {}".format(k_err))
      sys.exit(1)


  
  def get_key(self, key_name):
    '''
    Parameter: [key_name]  string of key to get from dictionary
    '''
    try:
      return self.json_data.get(key_name)
    except KeyError as k_err:
      logging.error("[!] Error could not obtain key %s" % str(k_err))
      sys.exit(1)
