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
    print >> sys.stderr, ('Error reading file %s: %s' %
                          (filename, e.strerror))
    return None
  contents = file.read()
  file.close()
  return contents


def PrintError(msg):
  print >> sys.stderr, 'error: %s' % msg


def CheckDecoder(asm, tmp, hexfile, gas, decoder):
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
  assert(len(offsets) < 2)
  if len(offsets) == 0:
    return (True, None)
  return (True, offsets[0])


def CompareOffsets(tmp, off_list, hexfile):
  output = ''
  for off in off_list:
    output += 'offset 0x%x: validation error\n' % off
  basename = os.path.basename(hexfile[:-4])
  WriteFile(os.path.join(tmp , basename + '.val.out'),
            output)
  golden = ReadFile(os.path.join('golden', basename + '.val.ref'))
  if output == golden:
    return True
  return False


class InstByteSequence:
  def __init__(self):
    self.inst_bytes = []
    self.offsets = {}

  def Parse(self, hexfile):
    off = 0
    inst_begin = 0
    for line in open(hexfile, 'r').readlines():
      inst_begin = off
      if line.startswith('#'):
        continue
      for word in line.rstrip().split(' '):
        assert(re.match(r'[0-9a-zA-Z][0-9a-zA-Z]', word))
        self.inst_bytes.append(word)
        off += 1
      self.offsets[inst_begin] = off

  def InstInBundle(self, inst_offset, bundle_start):
    assert(inst_offset in self.offsets)
    if bundle_start + 32 >= self.offsets[inst_offset]:
      return True
    return False

  def StuboutInst(self, offset):
    assert(offset in self.offsets)
    for off in xrange(offset, self.offsets[offset]):
      self.inst_bytes[off] = '90'

  def GenAsmBundle(self, start_offset):
    """
    Returns:
      A pair of (asm, next_offset), where:
      asm - text representing code for the bundle suitable as assembler input
      next_offset - offset of the instruction to start the next bundle from
    """
    assert(start_offset in self.offsets)
    off = start_offset
    asm = '.text\n'
    bytes_written = 0
    while True:
      sep = '.byte 0x'
      inst_fully_written = True
      for i in xrange(off, self.offsets[off]):
        asm += sep + self.inst_bytes[i]
        bytes_written += 1
        sep = ', 0x'
        if bytes_written == 32:
          inst_fully_written = False
          break
      asm += '\n'
      if inst_fully_written:
        off = self.offsets[off]
      if bytes_written == 32 or off == len(self.inst_bytes):
        break
    if off == len(self.inst_bytes):
      off = 0
    for i in xrange((32 - (bytes_written % 32)) % 32):
      asm += 'nop\n'
    return (asm, off)

  def GenAsm(self):
    """
      Returns text for all instructions suitable as assembler input
    """
    asm = '.text\n'
    off = 0
    while True:
      sep = '.byte 0x'
      for i in xrange(off, self.offsets[off]):
        asm += sep + self.inst_bytes[i]
        sep = ', 0x'
      off = self.offsets[off]
      asm += '\n'
      if off == len(self.inst_bytes):
        break
    return asm


def RunTest(tmp, gas, decoder, validator, test):
  hexfile = 'testdata/64/%s.hex' % test
  if not os.path.exists(hexfile):
    PrintError('%s: no such file' % hexfile)
    return False

  # Initialize the list of byte sequences representing instructions.
  hex_instructions = InstByteSequence()
  hex_instructions.Parse(hexfile)

  # Check disassembling of the whole input.
  if not CheckDecoder(hex_instructions.GenAsm(), tmp, hexfile, gas, decoder):
    return False

  # Cut the input instructions in bundles and run a test for each bundle.
  start_pos = 0
  runs = 0
  top_errors = []
  while True:
    (asm, next_pos) = hex_instructions.GenAsmBundle(start_pos)
    if next_pos == 0:
      break
    assert(asm)
    assert(start_pos < next_pos)
    # Collect erroreous offsets, stub them out, repeat until no error.
    while True:
      asmfile = os.path.basename(hexfile[:-4]) + ('_part%d.s' % runs)
      asmfile = os.path.join(tmp, asmfile)
      (status, err_offset) = CheckAsm(asm, asmfile, gas, validator)
      runs += 1
      if not status:
        return False
      if err_offset == None:
        break
      top_errors.append(start_pos + err_offset)
      # If the instruction crosses the bundle boundary no more error is
      # expected.
      if not hex_instructions.InstInBundle(err_offset, start_pos):
        break
      hex_instructions.StuboutInst(err_offset)
      (asm, unused_next_pos) = hex_instructions.GenAsmBundle(start_pos)

    start_pos = next_pos

  # Compare the collected offsets with the golden file.
  if not CompareOffsets(tmp, top_errors, hexfile):
    return False
  return True


def Main():
  parser = optparse.OptionParser()
  parser.add_option(
      '-t', '--tests', dest='tests',
#      default='rex_invalid,ud2,stack_regs,stosd67,mov-lea-rbp,valid_lea_store,mov-lea-rbp-bad-1,mov-esi-nop-use,mov-lea-rbp-bad-3,return,call-ex,data66prefix,maskmov_test,call1,rip-relative,incno67,hlt,change-subregs,pop-rbp,jump_not_atomic,invalid_base,jmp0,prefix-single,prefix-3,call_not_aligned,call_short,add_rsp_r15,segment_not_aligned,prefix-2,call0,invalid_base_store,add_mult_prefix,segment_store,lea-rsp,inc67,extensions,call_long,mov_rbp_2_rsp,rip67,movsbw,mv_ebp_add_crossing,sub-add-rsp,fs_use,cpuid,read_const_ptr,cmpxchg,jump_underflow,add_cs_gs_prefix,mov-lea-rbp-bad-5,nacl_illegal,rep_tests,mov-lea-rsp,legacy,test_insts,valid_base_only,mov-lea-rbp-bad-4,fpu,rdmsr,segment_assign,bad66,wrmsr,stosd,mv_ebp_alone,jump_overflow,jump_atomic,movlps-ex,3DNow,bsf-mask,mv_ebp_add_rbp_r15,jmp-16,nops,ambig-segment,update-rsp,bt,sub-rsp,strings,mov_esp_add_rsp_r15,sse,indirect_jmp_masked,movs_test,addrex,segment_aligned,addrex2,bsr-mask,stosd-bad,indirect_jmp_not_masked,call_aligned,rex_not_last,invalid_width_index,jump_outside,x87,mmx,rbp67,push-memoff,AhNotSubRsp,jump_not_atomic_1,call_not_aligned_16,mov-lea-rbp-bad-2,valid_and_store,stosdno67,lea,dup-prefix,stubseq,lea-add-rsp',
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
