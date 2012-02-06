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


def PrintError(msg):
  print >> sys.stderr, 'error: %s' % msg


def RunTest(tmp, gas, decoder, validator, test):
  hexfile = 'testdata/64/%s.hex' % test
  if not os.path.exists(hexfile):
    PrintError('%s: no such file' % hexfile)
    return False
  asm = '.text\n'
  bytes_written = 0
  for line in open(hexfile, 'r').readlines():
    if line.startswith('#'):
      asm += line
      continue
    sep = '.byte 0x'
    for word in line.rstrip().split(' '):
      assert(re.match(r'[0-9a-zA-Z][0-9a-zA-Z]', word))
      bytes_written += 1
      asm += sep + word
      sep = ', 0x'
    asm = asm + '\n'
  for i in xrange(32 - (bytes_written % 32)):
    asm += 'nop\n'
  asmfile = os.path.basename(hexfile[:-4]) + '.s'
  asmfile = os.path.join(tmp, asmfile)
  WriteFile(asmfile, asm)
  objfile = asmfile[:-2] + '.o'
  gas_command = [gas, asmfile, '-o', objfile]
  retcode = subprocess.call(gas_command)
  if retcode != 0:
    PrintError('error while executing command: %s' % ' '.join(gas_command))
    return False
  decoder_process = subprocess.Popen([decoder, objfile], stdout=subprocess.PIPE)
  (decode_out, decode_err) = decoder_process.communicate()
  # TODO: compare decoder with a golden file or objdump again ..
  print decode_out
  validator_process = subprocess.Popen([validator, objfile],
                                       stdout=subprocess.PIPE)
  (val_out, val_err) = validator_process.communicate()
  print 'stdout:'
  print val_out
  print 'stderr:'
  print val_err
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
