import r2pipe
import traceback
import logging

r2 = None
def r2_init(path):
  global r2
  r2 = r2pipe.open(path, ['-2'])

def r2_cmd(cmd):
  result = None
  try:
    result = r2.cmd(cmd)
  except:
    traceback.print_exc()
    logging.DEBUG('r2pipe cmd({}) error: {}'.format(cmd, e))
  return result
  
def r2_cmdj(cmd):
  result = None
  try:
    result = r2.cmdj(cmd)
  except r2pipe.cmdj.Error as e:
    logging.DEBUG('r2pipe cmdj({}) error: {}'.format(cmd, e))
  return result