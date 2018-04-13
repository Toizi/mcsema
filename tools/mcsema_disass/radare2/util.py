from logging import DEBUG, DEBUG_POP, DEBUG_PUSH
from r2_helper import r2_cmd, r2_cmdj
import CFG_pb2

BADADDR = None

IS_PE = None
IS_ELF = None
PTR_SIZE = None

# CCONV_TYPES = {
#   'C': CFG_pb2.ExternalFunction.CallerCleanup,
#   'E': CFG_pb2.ExternalFunction.CalleeCleanup,
#   'F': CFG_pb2.ExternalFunction.FastCall
# }

BINJA_CCONV_TYPES = {
  'cdecl': CFG_pb2.ExternalFunction.CallerCleanup,
  'stdcall': CFG_pb2.ExternalFunction.CalleeCleanup,
  'fastcall': CFG_pb2.ExternalFunction.FastCall,
  'amd64' : CFG_pb2.ExternalFunction.FastCall
}

def is_elf():
  global IS_ELF
  if IS_ELF is None:
    IS_ELF = r2_cmdj('iIj')['bintype'] == 'elf'
  return IS_ELF

def is_pe():
  global IS_PE
  if IS_PE is None:
    IS_PE = r2_cmdj('iIj')['bintype'] == 'pe'
  return IS_PE

def normalize_func_name(func_name):
  if func_name.startswith('sym.'):
    func_name = func_name[len('sym.'):]
  if func_name.startswith('imp.'):
    func_name = func_name[len('imp.'):]
  
  if func_name.startswith('sub.'):
    func_name = func_name[len('sub.'):]
  return func_name 

def get_address_size_in_bits():
  """Returns the available address size."""
  global PTR_SIZE
  if PTR_SIZE is None:
    PTR_SIZE = r2_cmdj('iIj')['bits']
  return PTR_SIZE

def get_address_size_in_bytes():
  return get_address_size_in_bits() / 8

def is_invalid_ea(ea):
  """Returns `True` if `ea` is not valid, i.e. it doesn't point into any
  valid segment."""
  if BADADDR == ea:
    return True

  # ?S works with symbols or addresses
  return r2_cmd('?S {}'.format(ea)) == ''

# TODO: how to implement?
def func_has_return_type(func):
  return False

def get_function_at(ea):
  '''[{"offset":4195840,"name":"entry0","size":41,"realsz":41,"cc":1,"cost":15,"nbbs":1,"edges":0,"ebbs":1,"calltype":"amd64","type":"fcn","minbound":"4195840","maxbound":"4195881","range":"41","diff":"NEW","callrefs":[],"datarefs":[4197072,4196960,4196205],"difftype":"new","indegree":0,"outdegree":0,"nargs":0,"nlocals":0}]'''
  func = r2_cmdj('afij {}'.format(ea))
  if not func:
    return None
  
  return func[0]

# from Adrian Herrera
# https://github.com/adrianherrera/mcsema/blob/getcfg_radare/tools/mcsema_disass/radare/r2_util.py
_FUNCTION_MAP = {}
def get_function(func_name, check_externals=False, default=None):
  """Get the start address of a function."""
  global _FUNCTION_MAP

  def get_func(func_name, check_externals=False, default=BADADDR):
    """Retrieve a function from the `_FUNCTION_MAP`."""
    # Check for the function name directly
    func = _FUNCTION_MAP.get(func_name)
    if func:
      return func

    # Check the symbol table
    func = _FUNCTION_MAP.get("sym.{}".format(func_name))
    if func:
      return func

    if not check_externals:
      # If we are not checking external functions and we have reached
      # this point, the function does not exist
      return default

    for prefix in ("sym.imp", "sub"):
      # Now check if the function is external
      func = _FUNCTION_MAP.get("{}.{}".format(prefix, func_name))
      if func:
        return func

    return default

  if _FUNCTION_MAP:
    return get_func(func_name, check_externals, default)

  # Build the function map if it does not already exist
  for func in r2_cmdj("aflj"):
    name = func.pop("name")
    _FUNCTION_MAP[name] = func

  return get_func(func_name, check_externals, default)

def get_function_ea(func_name, check_externals=False, default=BADADDR):
  func = get_function(func_name, check_externals, default)
  if func != default:
    return func['offset']
  return func

def loc_by_name(name):
  try:
    # ?X prints right hand side as hex
    # $$ is current address, @ is offset
    s = r2_cmd('?X $$ @ {}'.format(name))
    ea = int(s, base=16)
    return ea
  except:
    return BADADDR


def seg_has_flags(seg, flags):
  seg_flags = seg.get('flags')
  for flag in flags:
    if flag not in seg_flags:
      return False
  return True


def seg_start(ea):
  seg = get_seg(ea)
  if seg:
    return seg['vaddr']
  return BADADDR

def get_bytes(ea, size):
  b64_enc = r2_cmd('p6e {} @ {}'.format(size, ea))
  return b64_enc.decode('base64')

# ida's segments are actually sections
SECTIONS = {}

def get_seg(ea):
  global SECTIONS
  # populate once if unitilialized
  if not SECTIONS:
    secs = r2_cmdj('Sj')
    for sec in secs:
      name = sec['name'] 
      # r2 has an empty section for some reason
      if name:
        SECTIONS[name] = sec
  
  # r2 doesn't seem to provide a nice way to access sections
  # so we parse them manually
  for sec in SECTIONS.values():
    start_ea = sec['vaddr']
    end_ea = start_ea + sec['vsize']
    if start_ea <= ea and ea < end_ea:
      return sec
  return None

_NOT_EXTERNAL_SEGMENTS = set([BADADDR])
_EXTERNAL_SEGMENTS = set()

def is_external_segment(ea):
  """Returns `True` if the segment containing `ea` looks to be solely containing
  external references."""
  global _NOT_EXTERNAL_SEGMENTS

  seg_ea = seg_start(ea)
  if seg_ea in _NOT_EXTERNAL_SEGMENTS:
    return False

  if seg_ea in _EXTERNAL_SEGMENTS:
    return True

  # don't think r2 has something like this
  # if is_external_segment_by_flags(ea):
  #   _EXTERNAL_SEGMENTS.add(seg_ea)
  #   return True

  # ???
  # ext_types = []
  seg_name = get_seg(seg_ea)['name'].lower()
  # DEBUG('is_external_segment(0x{:x}), {}'.format(ea, seg_name))
  
  if is_elf():
    if ".got" in seg_name or ".plt" in seg_name:
      _EXTERNAL_SEGMENTS.add(seg_ea)
      return True

  elif is_pe():
    if ".idata" == seg_name:  # Import table.
      _EXTERNAL_SEGMENTS.add(seg_ea)
      return True

  _NOT_EXTERNAL_SEGMENTS.add(seg_ea)
  return False

def is_thunk(ea):
  """Returns true if some address is most likely a thunk."""
  # DEBUG('is_thunk(0x{:x})'.format(ea))
  func = r2_cmdj('pdfj @ {}'.format(ea))
  return len(func['ops']) == 1 and func['ops'][0]['opcode'].startswith('jmp')

def get_blocks_at(ea):
  '''returns a block in the form, # = optional
  {#"jump":4196486#,#"fail":4196446#,"addr":4196416,"size":30,"inputs":1,"outputs":2,"ninstr":10,"traced":false}'''
  blocks = r2_cmdj('afbj @ {}'.format(ea))
  return blocks

SYMBOLS = None
def find_symbol(ea):
  '''returns the symbol at the ea with the form
  {"name":"imp.__gmon_start__","demname":"","flagname":"loc.imp.__gmon_start","ordinal":7,"bind":"WEAK","size":16,"type":"NOTYPE","vaddr":4194304,"paddr":0}'''
  global SYMBOLS
  if SYMBOLS is None:
    symbol_list = r2_cmdj('isj')
    SYMBOLS = { sym['vaddr'] : sym for sym in symbol_list }
  sym = SYMBOLS.get(ea)
  return sym

  # sym_info = r2_cmdj('is.j @ {}'.format(ea))
  # name = ''
  # if sym_info:
  #   sym_info = sym_info.get('symbols')
  #   if sym_info:
  #     name = sym_info.get('name')
  # if name is None:
  #   return ''
  # DEBUG('find_symbol_name {:x} = {}'.format(ea, name))
  # return name
def find_symbol_name(ea):
  sym = find_symbol(ea)
  if sym:
    return sym['name']
  return ''

IMPORTED_SYMBOLS = None
def get_imported_symbols():
  '''dict of symbol name mapped to import,
  e.g. {"ordinal":1,"bind":"GLOBAL","type":"FUNC","name":"putchar","plt":4195696}'''
  global IMPORTED_SYMBOLS
  if not IMPORTED_SYMBOLS:
    symbols = r2_cmdj('iij')
    IMPORTED_SYMBOLS = symbols # { (s['name'],s) for s in symbols}
  return IMPORTED_SYMBOLS

def get_instruction_at(ea):
  insts = r2_cmdj('pdj 1 @ {}'.format(ea))
  if insts:
    return insts[0]
  return None
