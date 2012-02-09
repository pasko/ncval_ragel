#!/usr/bin/python
# Copyright (c) 2012 The Native Client Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Runs in-tree NaCl x86 validator tests against the DFA-based validator.

For tests an extra symlink is needed:
  cd ncval_ragel
  ln -s /path/to/native_client/src/trusted/validator_x86/testdata
"""

import optparse
import os
import re
import string
import subprocess
import sys


def WriteFile(filename, data):
  fh = open(filename, "w")
  try:
    fh.write(data)
  finally:
    fh.close()


def ReadFile(filename):
  try:
    file = open(filename, 'r')
  except IOError, e:
    print >> sys.stderr, ('I/O Error reading file %s: %s' %
                          (filename, e.strerror))
    return None
  contents = file.read()
  file.close()
  return contents


def PrintError(msg):
  print >> sys.stderr, 'error: %s' % msg


def CheckDecoder(insts, tmp, hexfile, gas, decoder):
  asm = '.text\n'
  for inst in insts:
    sep = '.byte 0x'
    for byte in inst:
        asm += sep + byte
        sep = ', 0x'
    asm += '\n'
  basename = os.path.basename(hexfile[:-4])
  asmfile = os.path.join(tmp , basename + '.all.s')
  objfile = basename + '.o'
  WriteFile(asmfile, asm)
  gas_cmd = [gas, asmfile, '-o', objfile]
  if subprocess.call(gas_cmd) != 0:
    PrintError('assembler failed to execute command: %s' % gas_cmd)
    return False
  decoder_process = subprocess.Popen([decoder, objfile], stdout=subprocess.PIPE)
  (decode_out, decode_err) = decoder_process.communicate()
  WriteFile(os.path.join(tmp, basename + '.all.decode.out'), decode_out)
  # TODO: compare with objdump
  return True


def CheckAsm(asm, asmfile, gas, validator):
  WriteFile(asmfile, asm)
  basename = asmfile[:-2]
  objfile = basename + '.o'
  if subprocess.call([gas, asmfile, '-o', objfile]) != 0:
    return (False, [])
  validator_process = subprocess.Popen([validator, objfile],
                                       stdout=subprocess.PIPE)
  (val_out, val_err) = validator_process.communicate()
  offsets = []
  for line in string.split(val_out, '\n'):
    re_match = re.match(r'offset ([^:]+):.+', line)
    if not re_match:
      continue
    offsets.append(int(re_match.group(1), 16))
  return (True, offsets)


def FillOneBundle(start_pos, total_bytes, insts):
  new_pos = start_pos
  bytes_written = 0
  seen_bytes = 0
  asm = '.text\n'
  for inst in insts:
    sep = '.byte 0x'
    new_pos = start_pos + bytes_written
    for byte in inst:
      if seen_bytes >= start_pos:
        asm += sep + byte
        bytes_written += 1
        if bytes_written == 32:
          break
        sep = ', 0x'
      seen_bytes += 1
    if seen_bytes >= start_pos:
      asm += '\n'
    if bytes_written == 32:
      break
  if bytes_written == 0:
    return (None, None)
  for i in xrange((32 - (bytes_written % 32)) % 32):
    asm += 'nop\n'
  if start_pos + bytes_written == total_bytes:
    return (asm, total_bytes)
  return (asm, new_pos)


def CompareOffsets(tmp, off_list, hexfile):
  output = ''
  for off in off_list:
    output += 'offset 0x%x: validation error\n' % off
  WriteFile(os.path.join(tmp , os.path.basename(hexfile[:-4]) + '.val.out'),
            output)
  golden = ReadFile(hexfile[:-4] + '.val.ref')
  if output == golden:
    return True
  return False


def RunTest(tmp, gas, decoder, validator, test):
  hexfile = 'testdata/64/%s.hex' % test
  if not os.path.exists(hexfile):
    PrintError('%s: no such file' % hexfile)
    return False

  # Initialize the list of byte sequences representing instructions.
  hex_instructions = []
  total_bytes = 0
  for line in open(hexfile, 'r').readlines():
    if line.startswith('#'):
      continue
    one_inst = []
    for word in line.rstrip().split(' '):
      assert(re.match(r'[0-9a-zA-Z][0-9a-zA-Z]', word))
      one_inst.append(word)
      total_bytes += 1
    if len(one_inst) != 0:
      hex_instructions.append(one_inst)

  # Check disassembling of the whole input.
  if not CheckDecoder(hex_instructions, tmp, hexfile, gas, decoder):
    return False

  # Cut the input instructions in bundles and run a test for each bundle.
  start_pos = 0
  runs = 0
  top_errors = []
  while True:
    (asm, next_pos) = FillOneBundle(start_pos, total_bytes, hex_instructions)
    if not asm:
      break
    assert(start_pos < next_pos)
    start_pos = next_pos
    asmfile = os.path.basename(hexfile[:-4]) + ('_part%d.s' % runs)
    asmfile = os.path.join(tmp, asmfile)
    (status, err_offsets) = CheckAsm(asm, asmfile, gas, validator)
    if not status:
      return False
    runs += 1

    # Collect offsets where validation errors occurred.
    for off in err_offsets:
      top_errors.append(start_pos + off)

  # Compare the collected offsets with the golden file.
  if not CompareOffsets(tmp, top_errors, hexfile):
    return False
  return True


def Main():
  parser = optparse.OptionParser()
  parser.add_option(
      '-t', '--tests', dest='tests',
      default='bt',
      help='a comma-separated list of tests')
  parser.add_option(
      '-a', '--gas', dest='gas',
      default=None,
      help='path to assembler')
  parser.add_option(
      '-d', '--decoder', dest='decoder',
      default=None,
      help='path to decoder')
  parser.add_option(
      '-v', '--validator', dest='validator',
      default=None,
      help='path to validator')
  parser.add_option(
      '-p', '--tmp', dest='tmp',
      default=None,
      help='a directory for storing temporary files')
  opt, args = parser.parse_args()
  if (args or
      not opt.tmp or
      not opt.gas or
      not opt.decoder or
      not opt.validator):
    parser.error('invalid arguments')
  no_failures = True
  for tst in string.split(opt.tests, ','):
    if RunTest(opt.tmp, opt.gas, opt.decoder, opt.validator, tst):
      print '%s: PASS' % tst
    else:
      print '%s: FAIL' % tst
      no_failures = False
  if no_failures:
    print 'All tests PASSed'
  else:
    print 'Some tests FAILed'
    return 1
  return 0


if __name__ == '__main__':
  sys.exit(Main())
