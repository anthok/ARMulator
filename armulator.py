__author__ = "Kyle Anthony"

import argparse
import sys
import os
import logging

try:
  from unicorn import *
  from unicorn.arm_const import *
  from lib import configloader,engine
except ImportError as i_err:
  logging.error("[-] Error, could not import %s" % str(i_err))


def is_valid_file(parser, arg):
  '''
  Purpose: Validate the file exists
  Parameters: [parser] argparse variable
              [arg] 
  '''
  if not os.path.exists(arg):
    parser.error("The file %s does not exist!" % arg)
  else:
    return arg  # return valid path

if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='Emulate ARM code with given RAM and Load Address')
  parser.add_argument('code',type=lambda x: is_valid_file(parser, x), help='ARM code to execute')
  parser.add_argument('config_path',type=lambda x: is_valid_file(parser, x), help='Config Path')
  args = parser.parse_args()

  if os.stat(args.code).st_size == 0:
    logging.error('[X] Error, no code contents')
    sys.exit(1)

  if os.stat(args.config_path).st_size == 0:
    logging.error('[X] Error, no config contents')
    sys.exit(1)
    
  code = None
  with open(args.code,'rb') as fh:
    code = fh.read()

  config = configloader.JSONLoad(args.config_path, verbose=False)
  eng = engine.EmulationEngine(code,config)
  eng.emulate()
