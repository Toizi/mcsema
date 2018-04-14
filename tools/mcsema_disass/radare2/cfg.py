import argparse
import CFG_pb2
import os
from Queue import Queue
from collections import defaultdict
from r2_helper import r2_cmd, r2_cmdj, r2_init
from util import *
from logging import DEBUG, DEBUG_POP, DEBUG_PUSH, INIT_DEBUG_FILE
import xrefs
from string import ascii_uppercase
from binascii import unhexlify

base_dir = os.path.dirname(os.path.abspath(__file__))
tools_disass_dir = os.path.dirname(base_dir)

_CFG_INST_XREF_TYPE_TO_NAME = {
    CFG_pb2.CodeReference.ImmediateOperand: "imm",
    CFG_pb2.CodeReference.MemoryOperand: "mem",
    CFG_pb2.CodeReference.MemoryDisplacementOperand: "disp",
    CFG_pb2.CodeReference.ControlFlowOperand: "flow"
}

EXTERNAL_FUNCS_TO_RECOVER = {}
EXTERNAL_VARS_TO_RECOVER = {}

RECOVERED_EAS = set()
ACCESSED_VIA_JMP = set()

TO_RECOVER = {
  "stack_var" : False,
}

RECOVERED = set()
TO_RECOVER = Queue()

def queue_func(addr):
  if addr not in RECOVERED:
    TO_RECOVER.put(addr)

#       so we can reuse the external info in recover function
# Map of external functions names to a tuple containing information like the
# number of arguments and calling convention of the function.
EMAP = {}

# Map of external variable names to their sizes, in bytes.
EMAP_DATA = {}

# `True` if we are getting the CFG of a position independent executable. This
# affects heuristics like trying to turn immediate operands in instructions
# into references into the data.
PIE_MODE = False

# Name of the operating system that runs the program being lifted. E.g. if
# we're lifting an ELF then this will typically be `linux`.
OS_NAME = ""

# Set of substrings that can be found inside of symbol names that are usually
# signs that the symbol is external. For example, `stderr@@GLIBC_2.2.5` is
# really the external `stderr`, so we want to be able to chop out the `@@...`
# part to resolve the "true" name. There are a lot of `@@` variants in PE files,
# e.g. `@@QEAU_..`, `@@AEAV..`, though these are likely for name mangling.
EXTERNAL_NAMES = ("@@GLIBC_", )

_NOT_ELF_BEGIN_EAS = (0xffffffffL, 0xffffffffffffffffL)

# Set of symbols that IDA identifies as being "weak" symbols. In ELF binaries,
# a weak symbol is kind of an optional linking thing. For example, the 
# `__gmon_start__` function is referenced as a weak symbol. This function is
# used for gcov-based profiling. If gcov is available, then this symbol will
# be resolved to a real function, but if not, it will be NULL and programs
# will detect it as such. An example use of a weak symbol in C would be:
#
#     extern void __gmon_start__(void) __attribute__((weak));
#     ...
#     if (__gmon_start__) {
#       __gmon_start__();
#     }
WEAK_SYMS = set()

# Used to track thunks that are actually implemented. For example, in a static
# binary, you might have a bunch of calls to `strcpy` in the `.plt` section
# that go through the `.plt.got` to call the implementation of `strcpy` compiled
# into the binary.
INTERNALLY_DEFINED_EXTERNALS = {}  # Name external to EA of internal.
INTERNAL_THUNK_EAS = {}  # EA of thunk to EA of implementation.

def parse_os_defs_file(df):
  """Parse the file containing external function and variable
  specifications."""
  global OS_NAME, WEAK_SYMS, EMAP, EMAP_DATA
  global _FIXED_EXTERNAL_NAMES, INTERNALLY_DEFINED_EXTERNALS
  
  is_linux = OS_NAME == "linux"
  for l in df.readlines():
    #skip comments / empty lines
    l = l.strip()
    if not l or l[0] == "#":
      continue

    if l.startswith('DATA:'):
      # process as data
      (marker, symname, dsize) = l.split()
      if 'PTR' in dsize:
        dsize = get_address_size_in_bytes()

      EMAP_DATA[symname] = int(dsize)

    else:
      fname = args = conv = ret = sign = None
      line_args = l.split()

      if len(line_args) == 4:
        (fname, args, conv, ret) = line_args
      elif len(line_args) == 5:
        (fname, args, conv, ret, sign) = line_args

      if conv == "C":
        realconv = CFG_pb2.ExternalFunction.CallerCleanup
      elif conv == "E":
        realconv = CFG_pb2.ExternalFunction.CalleeCleanup
      elif conv == "F":
        realconv = CFG_pb2.ExternalFunction.FastCall
      else:
        DEBUG("ERROR: Unknown calling convention: {}".format(l))
        continue

      if ret not in "YN":
        DEBUG("ERROR: Unknown return type {} in {}".format(ret, l))
        continue

      ea = get_function_ea(fname, check_externals=True)

      if not is_invalid_ea(ea):
        # DEBUG("Valid ea func {} at 0x{:x}".format(fname, ea))
        if not is_external_segment(ea) and not is_thunk(ea):
          DEBUG("Not treating {} as external, it is defined at {:x}".format(
              fname, ea))
          INTERNALLY_DEFINED_EXTERNALS[fname] = ea
          continue

        # TODO: look into what this does
        # Misidentified and external. This comes up often in PE binaries, for
        # example, we will have the following:
        #
        #   .idata:01400110E8 ; void __stdcall EnterCriticalSection(...)
        #   .idata:01400110E8     extrn EnterCriticalSection:qword
        #
        # Really, we want to try this as code.
        # flags = idc.GetFlags(ea)
        # if not idc.isCode(flags) and not idaapi.is_weak_name(ea):
        #   seg_name = idc.SegName(ea).lower()
        #   if ".idata" in seg_name:
        #     EXTERNAL_FUNCS_TO_RECOVER[ea] = fname

        #   # Refer to issue #308
        #   else:
        #     DEBUG("WARNING: External {} at {:x} from definitions file may not be a function".format(
        #       fname, ea))

      EMAP[fname] = (int(args), realconv, ret, sign)

      # Sometimes there will be things like `__imp___gmon_start__` which
      # is really the implementation of `__gmon_start__`, where that is
      # a weak symbol.
      if is_linux:
        imp_name = "__imp_{}".format(fname)

        if loc_by_name(imp_name):
          _FIXED_EXTERNAL_NAMES[imp_name] = fname
          WEAK_SYMS.add(fname)
          WEAK_SYMS.add(imp_name)

  # DEBUG('')
  df.close()

def find_entry(arg_entry):#, symbols):
  DEBUG('Finding entry point')
  # for symbol in symbols:
  #   if symbol['name'] == arg_entry:
  #     entry_ea = symbol['vaddr']
  #     break
  # # entry not found through symbols. if main is requested,
  # # check if radare managed to find it
  # if entry_ea == -1 and arg_entry == 'main':
  #   DEBUG('main not found in symbols. checking if r2 identified it')
  #   hex_ea = r2_cmd('afo main')
  #   if hex_ea:
  #     entry_ea = int(hex_ea, base=16)
  #     DEBUG('r2 found main at 0x{:x}'.format(entry_ea))
  entry_ea = loc_by_name(arg_entry)
  

  if entry_ea == BADADDR:
    entry_ea = r2_cmdj('iej')[0]['vaddr']
    DEBUG('Entry point {} could not be found. Using file entry 0x{:x}'.format(
      arg_entry, entry_ea
    ))
  
  DEBUG('Entry point: 0x{:x}'.format(entry_ea))
  return entry_ea


def add_block(pb_func, block):
  """
  Args:
    pb_func (CFG_pb2.Function)
    block ( block dict)

  Returns:
    CFG_pb2.Block
  """
  block_start = block['addr']
  DEBUG("BB: {:x}".format(block_start))
  pb_block = pb_func.blocks.add()
  pb_block.ea = block_start
  successors = []
  successors.append(block.get('jump'))
  successors.append(block.get('fail'))
  pb_block.successor_eas.extend(
    [b for b in successors if b is not None])
  return pb_block


def get_xrefs(func, inst):
  global _LAST_UNUSED_REFS

  refs = set()

  inst_type = inst['type']
  ea_next = inst['offset'] + inst['size']
  if inst_type == 'call':
    refs.add(xrefs.XRef(inst['jump'], xrefs.XRef.CONTROLFLOW))
  elif inst_type == 'jmp':
    jump = inst.get('jump')
    fail = inst.get('fail')
    # filter regular control flow
    if jump is not None and ea_next != jump:
      refs.add(xrefs.XRef(jump, xrefs.XRef.CONTROLFLOW))
    if fail is not None and ea_next != fail:
      refs.add(xrefs.XRef(fail, xrefs.XRef.CONTROLFLOW))
  # basic reference checking for now
  # simply look at whether the ptr
  else:
    ptr = inst.get('ptr')
    if not is_invalid_ea(ptr):
      refs.add(xrefs.XRef(ptr, xrefs.XRef.IMMEDIATE))

  # dis = bv.get_disassembly(il.address)

  # # TODO(pag): This is an ugly hack for the ADRP instruction on AArch64.
  # ref = _get_aarch64_partial_xref(bv, func, il, dis)
  # if ref is not None:
  #   refs.add(ref)
  # else:
  #   reftype = XRef.IMMEDIATE

  #   # PC-relative displacement for AArch64's `adr` instruction.
  #   if func.arch.name == 'aarch64' and dis.startswith('adr '):
  #     reftype = XRef.DISPLACEMENT

  #   _fill_xrefs_internal(bv, il, refs, reftype)

  #   # TODO(pag): Another ugly hack to deal with a specific flavor of jump
  #   #            table that McSema doesn't handle very well. The specific form
  #   #            is:
  #   #
  #   #    .text:00000000004009AC ADRP            X1, #asc_400E5C@PAGE ; "\b"
  #   #    .text:00000000004009B0 ADD             X1, X1, #asc_400E5C@PAGEOFF ; "\b"
  #   #    .text:00000000004009B4 LDR             W0, [X1,W0,UXTW#2]
  #   #    .text:00000000004009B8 ADR             X1, loc_4009C4   <-- point to a block
  #   #    .text:00000000004009BC ADD             X0, X1, W0,SXTW#2
  #   #    .text:00000000004009C0 BR              X0
  #   #
  #   #            We don't have good ways of referencing basic blocks, so if we
  #   #            left the reference from `4009B8` to `4009C4`, then that would
  #   #            be computed in terms of the location in memory of the copied
  #   #            `.text` segment in the lifted binary.
  #   #
  #   #            We could handle this via a jump-offset table with offset of
  #   #            `4009B8`, but we don't yet support this variant of jump table
  #   #            in jmptable.py.
  #   if dis.startswith('adr ') and len(refs):
  #     ref = refs.pop()
  #     if util.is_code(bv, ref.addr) and not bv.get_function_at(ref.addr):
  #       DEBUG("WARNING: Omitting reference to non-function code address {:x}".format(ref.addr))
  #     else:
  #       refs.add(ref)  # Add it back in.

  DEBUG('get_xrefs, refs: {}'.format(refs))
  return refs

def add_xref(pb_inst, target, mask, optype):
  xref = pb_inst.xrefs.add()
  xref.ea = target
  xref.operand_type = optype

  debug_mask = ""
  if mask:
    xref.mask = mask
    debug_mask = " & {:x}".format(mask)

  sym_name = find_symbol_name(target)
  if len(sym_name) > 0:
    sym_name = normalize_func_name(sym_name)
    xref.name = sym_name

  seg = get_seg(target)
  if seg_has_flags(seg, 'x'):
    xref.target_type = CFG_pb2.CodeReference.CodeTarget
    debug_type = "code"
  else:
    xref.target_type = CFG_pb2.CodeReference.DataTarget
    debug_type = "data"

  if is_external_segment(target):
    xref.location = CFG_pb2.CodeReference.External
    debug_loc = "external"
  else:
    xref.location = CFG_pb2.CodeReference.Internal
    debug_loc = "internal"

  # If the target happens to be a function, queue it for recovery
  if get_function_at(target) is not None:
    queue_func(target)

  debug_op = _CFG_INST_XREF_TYPE_TO_NAME[optype]

  return "({} {} {} {:x}{} {})".format(
      debug_type, debug_op, debug_loc, target, debug_mask, sym_name)


def recover_inst(func, pb_block, pb_inst, inst, is_last):
  """
  Args:
    r2 (pipe)
    func ()
    pb_inst (CFG_pb2.Instruction)
  """
  pb_inst.ea = inst['offset']
  pb_inst.bytes = unhexlify(inst['bytes'].encode())

  # Search all il instructions at the current address for xrefs
  refs = set()
  refs = get_xrefs(func, inst)
  
  debug_refs = []

  # Add all discovered xrefs to pb_inst
  for ref in refs:
    debug_refs.append(add_xref(pb_inst, ref.addr, ref.mask, ref.cfg_type))

  if is_local_noreturn(inst):
    pb_inst.local_noreturn = True

  # # Add the target of a tail call as a successor
  # if util.is_jump_tail_call(bv, il):
  #   tgt = il.dest.constant
  #   pb_block.successor_eas.append(tgt)

  # table = jmptable.get_jmptable(bv, il)
  # if table is not None:
  #   debug_refs.append(add_xref(bv, pb_inst, table.base_addr, 0, CFG_pb2.CodeReference.MemoryDisplacementOperand))
  #   JMP_TABLES.append(table)

  #   # Add any missing successors
  #   for tgt in table.targets:
  #     if tgt not in pb_block.successor_eas:
  #       pb_block.successor_eas.append(tgt)

  DEBUG("I: {:x} {}".format(inst['offset'], " ".join(debug_refs)))

  if is_last:
    if len(pb_block.successor_eas):
      DEBUG("  Successors: {}".format(", ".join("{:x}".format(ea) for ea in pb_block.successor_eas)))
    else:
      DEBUG("  No successors")

def is_local_noreturn(inst):
  """Returns `True` if the instruction `arg`, or at `arg`, will terminate
  control flow."""
  if isinstance(inst, (int, long)):
    inst = get_instruction_at(inst)

  if inst['type'] == 'call' or inst['type'] == 'jmp':
    called_ea = inst['jump']
    return is_noreturn_function(called_ea)

  return inst['type'] == 'trap'


def is_noreturn_function(ea):
  func = r2_cmdj('pdfj @ {}'.format(ea))
  if func is None:
    return False

  func_name = normalize_func_name(func['name'])
  ext_func = EMAP.get(func_name)
  if ext_func:
    args, cconv, ret, sign = ext_func
    noret = ret == 'Y'
    if noret:
      DEBUG('noreturn (defs) function at 0x{:x}'.format(ea))
    return noret
  
  no_rets = r2_cmd('tn').splitlines()
  if func_name in no_rets:
    return True
  
  op = func['ops'][-1]
  noret = op['type'] != 'ret'
  if noret:
    DEBUG('noreturn (type) function at 0x{:x}'.format(ea))
  return noret

  return False
    

def recover_function(pb_mod, addr, is_entry=False):
  func = get_function_at(addr)
  if func is None:
    DEBUG('No function defined at 0x{:x}, skipping'.format(addr))
    return

  func_name = normalize_func_name(func['name'])
  if func_name in EMAP:
    # Externals are recovered later, skip this
    DEBUG("Skipping external function '{}' in main CFG recovery".format(func_name))
    return

  # Initialize the protobuf for this function
  DEBUG("Recovering function {} at {:x}".format(func_name, addr))

  pb_func = pb_mod.funcs.add()
  pb_func.ea = addr
  pb_func.is_entrypoint = is_entry
  pb_func.name = func_name 

  # Recover all basic blocks
  # il_groups = util.collect_il_groups(func.lifted_il)
  var_refs = defaultdict(list)
  for block in get_blocks_at(func['offset']):
    DEBUG_PUSH()
    pb_block = add_block(pb_func, block)
    DEBUG_PUSH()
    
    # Recover every instruction in the block
    insts = r2_cmdj('pdbj @ {}'.format(block['addr']))
    for inst in insts:
      # # Skip over anything that isn't an instruction
      # if inst.tokens[0].type != InstructionTextTokenType.InstructionToken:
      #   continue
      # il = func.get_lifted_il_at(inst.address)
      # all_il = il_groups[inst.address]

      pb_inst = pb_block.instructions.add()
      recover_inst(func, pb_block, pb_inst, inst, is_last=inst==insts[-1])

      # # Find any references to stack vars in this instruction
      # if RECOVER_OPTS['stack_vars']:
      #   vars.find_stack_var_refs(bv, inst, il, var_refs)

    DEBUG_POP()
    DEBUG_POP()

  # # Recover stack variables
  # if RECOVER_OPTS['stack_vars']:
  #   vars.recover_stack_vars(pb_func, func, var_refs)

def recover_sections(pb_mod):
  # Collect all address to split on
  # sec_addrs = set()
  # for sect in bv.sections.values():
  #   sec_addrs.add(sect.start)
  #   sec_addrs.add(sect.end)

  # global_starts = [gvar.ea for gvar in pb_mod.global_vars]
  # sec_addrs.update(global_starts)

  # # Process all the split segments
  # sec_splits = sorted(list(sec_addrs))
  # for start_addr, end_addr in zip(sec_splits[:-1], sec_splits[1:]):
  for sec in r2_cmdj('iSj'):#SECTIONS.values():
    start_addr = sec['vaddr']
    if start_addr == 0:
      continue
    end_addr = start_addr + sec['vsize']
    name = sec['name']
    # if seg_has_flags(sec, 'm'):
    if name[0] in ascii_uppercase:
      continue
    # real_sect = util.get_section_at(bv, start_addr)

    # # Ignore any gaps
    # if real_sect is None:
    #   continue

    DEBUG("Recovering [{:x}, {:x}, {}) from segment {}".format(
        start_addr, end_addr, sec, name))

    pb_seg = pb_mod.segments.add()
    pb_seg.name = name
    pb_seg.ea = start_addr
    pb_seg.data = get_bytes(start_addr, end_addr - start_addr)
    pb_seg.is_external = is_external_segment(start_addr)
    pb_seg.read_only = not seg_has_flags(sec, 'w')
    pb_seg.is_thread_local = False#util.is_tls_section(bv, start_addr)

    # sym = bv.get_symbol_at(start_addr)
    # pb_seg.is_exported = sym is not None and start_addr in global_starts
    # if pb_seg.is_exported and sym.name != real_sect.name:
    #   pb_seg.variable_name = sym.name
    pb_seg.variable_name = sec['name']
    pb_seg.is_exported = False

    # recover_section_vars(bv, pb_seg, start_addr, end_addr)
    # recover_section_cross_references(bv, pb_seg, real_sect, start_addr, end_addr)


def recover_ext_func(pb_mod, sym):
  """ Recover external function information
  Uses the map of predefined externals if possible

  Args:
    pb_mod (CFG_pb2.Module)
    sym (r2 symbol dict)
  """
  sym_name = sym['name']
  sym_ea = sym['plt']
  DEBUG("Recovering external function {} at {:x}".format(sym_name, sym_ea))

  func = get_function_at(sym_ea)
  if func is None:
    WARN("get_function_at {:x} returned None. skipping {}".format(sym_ea, sym_name))
    return

  eas = [sym_ea]
  # check if this is a thunk. if it is, add the same info as we just did
  if is_thunk(sym_ea):
    thunk_refs = func['datarefs']
    if len(thunk_refs) != 1:
      WARN("what appears to be a thunk at {:x} contains either no or multiple data refs".format(sym_ea))
    else:
      thunk_ea = thunk_refs[0]
      DEBUG('Found thunk at {:x} for {}'.format(thunk_ea, sym_name))
      eas.append(thunk_ea)
  
  # thunk and external will both have the same info other than ea
  for sym_ea in eas:
    if sym_name in EMAP:
      DEBUG('Found defined external function: {} @ {:x}'.format(sym_name, sym_ea))
      args, cconv, ret, sign = EMAP[sym_name]

      pb_extfn = pb_mod.external_funcs.add()
      pb_extfn.name = sym_name
      pb_extfn.ea = sym_ea
      pb_extfn.argument_count = args
      pb_extfn.cc = cconv
      pb_extfn.has_return = func_has_return_type(func)
      pb_extfn.no_return = ret == 'Y'
      pb_extfn.is_weak = sym['bind'] == 'WEAK'

    else:
      WARN("External function is not part of defs file")

      # ftype = func.function_type

      pb_extfn = pb_mod.external_funcs.add()
      pb_extfn.name = sym_name
      pb_extfn.ea = sym_ea
      pb_extfn.argument_count = func['nargs']
      pb_extfn.has_return = func_has_return_type(func)
      pb_extfn.no_return = False # TODO not ftype.can_return
      pb_extfn.is_weak = sym['bind'] == 'WEAK'

      # Assume cdecl if the type is unknown
      cconv = func.get('calltype')
      if cconv is not None and cconv in RADARE_CCONV_TYPES:
        pb_extfn.cc = RADARE_CCONV_TYPES[cconv]
      else:
        pb_extfn.cc = CFG_pb2.ExternalFunction.CallerCleanup


def recover_ext_var(pb_mod, sym):
  """ Recover external variable information

  Args:
    pb_mod (CFG_pb2.Module)
    sym (r2 symbol dict)
  """
  if sym.name in EXT_DATA_MAP:
    DEBUG("Recovering external variable {} at {:x}".format(sym.name, sym.address))

    pb_extvar = pb_mod.external_vars.add()
    pb_extvar.name = sym.name
    pb_extvar.ea = sym.address
    pb_extvar.size = EXT_DATA_MAP[sym.name]
    pb_extvar.is_weak = False  # TODO: figure out how to decide this
    pb_extvar.is_thread_local = util.is_tls_section(bv, sym.address)
  else:
    ERROR("Unknown external variable {} at {:x}".format(sym.name, sym.address))

def recover_externals(pb_mod):
  """Recover info about all external symbols"""
  DEBUG("Recovering externals")
  DEBUG_PUSH()
  for sym in get_imported_symbols():
    if sym['type'] == 'FUNC':
      recover_ext_func(pb_mod, sym)

    # TODO: what is type string in r2 of imported var
    if sym['type'] == 'VAR':
      recover_ext_var(pb_mod, sym)
  DEBUG_POP()

def recover_cfg(args):
  M = CFG_pb2.Module() 
  M.name = os.path.basename(args.binary)

  # symbols = r2_cmdj('isj')
  entry_ea = find_entry(args.entrypoint) #, symbols)

  # Recover the entrypoint func separately
  DEBUG('Recovering CFG')
  recover_function(M, entry_ea, is_entry=True)

  # Recover any discovered functions until there are none left
  while not TO_RECOVER.empty():
    addr = TO_RECOVER.get()

    if addr in RECOVERED:
      continue
    RECOVERED.add(addr)

    recover_function(M, addr)

  # DEBUG('Recovering Globals')
  # vars.recover_globals(M)

  DEBUG('Processing Segments')
  recover_sections(M)

  DEBUG('Recovering Externals')
  recover_externals(M)

  return M

def get_cfg(args, fixed_args):
  # Parse any additional args
  parser = argparse.ArgumentParser()

  parser.add_argument(
      '--recover-stack-vars',
      help='Flag to enable stack variable recovery',
      default=False,
      action='store_true')

  extra_args = parser.parse_args(fixed_args)

  if args.log_file != os.devnull:
    INIT_DEBUG_FILE(args.log_file)
    DEBUG('Debugging is enabled')

  else:
    INIT_DEBUG_FILE(os.sys.stdout)
    DEBUG('Debugging is enabled')
#   if extra_args.recover_stack_vars:
#     RECOVER_OPTS['stack_vars'] = True

  # Load the binary in radare
  r2_init(args.binary)

  DEBUG('Running analysis')
  r2_cmd('aaaa')

  def_paths = set(map(os.path.abspath, args.std_defs))
  
  os_defs_file = os.path.join(tools_disass_dir, "defs", "{}.txt".format(args.os))
  if os.path.isfile(os_defs_file):
    def_paths.add(os_defs_file)

  if def_paths:
    # Collect all paths to defs files
    DEBUG('Parsing definitions files')
  else:
    DEBUG('No definition files found')
  # Parse all of the defs files
  for fpath in def_paths:
    if os.path.isfile(fpath):
      with open(fpath, 'r') as df:
        DEBUG('Parsing def file {}'.format(fpath))
        parse_os_defs_file(df)
    else:
      DEBUG('{} is not a file'.format(fpath))

  # Recover module
  DEBUG('Starting recovery')
  pb_mod = recover_cfg(args)

  # Save cfg
  DEBUG('Saving to file: {}'.format(args.output))
  with open(args.output, 'wb') as f:
    f.write(pb_mod.SerializeToString())
  # debugging
  with open(args.output + '.txt', 'wb') as f:
    f.write(pb_mod.__str__())

  return 0
