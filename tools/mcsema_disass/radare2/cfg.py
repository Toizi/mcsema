import argparse

def get_cfg(args, fixed_args):
  # Parse any additional args
  parser = argparse.ArgumentParser()

  parser.add_argument(
      '--recover-stack-vars',
      help='Flag to enable stack variable recovery',
      default=False,
      action='store_true')

  extra_args = parser.parse_args(fixed_args)

#   if extra_args.recover_stack_vars:
#     RECOVER_OPTS['stack_vars'] = True

#   # Setup logger
#   util.init_logger(args.log_file)

#   # Load the binary in binja
#   bv = util.load_binary(args.binary)

#   # Once for good measure.
#   bv.add_analysis_option("linearsweep")
#   bv.update_analysis_and_wait()

#   # Twice for good luck!
#   bv.add_analysis_option("linearsweep")
#   bv.update_analysis_and_wait()

#   # Collect all paths to defs files
#   log.debug('Parsing definitions files')
#   def_paths = set(map(os.path.abspath, args.std_defs))
#   def_paths.add(os.path.join(DISASS_DIR, 'defs', '{}.txt'.format(args.os)))  # default defs file

#   # Parse all of the defs files
#   for fpath in def_paths:
#     if os.path.isfile(fpath):
#       parse_defs_file(bv, fpath)
#     else:
#       log.warn('%s is not a file', fpath)

#   # Recover module
#   log.debug('Starting analysis')
#   pb_mod = recover_cfg(bv, args)

#   # Save cfg
#   log.debug('Saving to file: %s', args.output)
#   with open(args.output, 'wb') as f:
#     f.write(pb_mod.SerializeToString())

  return 0
