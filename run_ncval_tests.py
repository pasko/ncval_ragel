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
  asmfile = os.path.join(tmp, basename + '.all.s')
  objfile = os.path.join(tmp, basename + '.o')
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


def CompareOffsets(tmp, off_info, hexfile):
  output = ''
  for off, msg_list in sorted(off_info.iteritems()):
    for msg in msg_list:
      output += 'offset 0x%x: %s\n' % (off, msg)
  basename = os.path.basename(hexfile[:-4])
  output_file = os.path.join(tmp , basename + '.val.out')
  WriteFile(output_file, output)
  golden_file = os.path.join('golden', basename + '.val.ref')
  golden = ReadFile(golden_file)
  if output == golden:
    return True
  PrintError('files differ: %s %s' % (golden_file, output_file))
  return False


class InstByteSequence:
  def __init__(self):
    self.inst_bytes = []
    self.offsets = {}

  def Parse(self, hexfile):
    # print 'parsing %s' % hexfile
    off = 0
    inst_begin = 0
    for line in open(hexfile, 'r').readlines():
      inst_begin = off
      if line.startswith('#'):
        continue
      for word in line.rstrip().split(' '):
        if re.match(r'^\s*$', word):
          continue
        assert(re.match(r'[0-9a-zA-Z][0-9a-zA-Z]', word))
        self.inst_bytes.append(word)
        off += 1
      self.offsets[inst_begin] = off

  def HasOffset(self, offset):
    return offset in self.offsets

  def InstInBundle(self, inst_offset, bundle_start):
    assert((bundle_start + inst_offset) in self.offsets)
    if bundle_start + 32 >= self.offsets[bundle_start + inst_offset]:
      return True
    return False

  def OffsetBelongsToInst(self, offset, inst_start):
    assert(inst_start in self.offsets)
    if offset == inst_start:
      return True
    for i in xrange(inst_start, len(self.inst_bytes)):
      if self.HasOffset(i):
        return False
      if i == offset:
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
    off = start_offset
    asm = '.text\n'
    bytes_written = 0

    # Allow to start from offset that does not start an instruction.
    sep = '.byte 0x'
    while off < len(self.inst_bytes):
      if off in self.offsets:
        break
      asm += sep + self.inst_bytes[off]
      sep = ', 0x'
      bytes_written += 1
      off += 1
    if bytes_written > 0:
      asm += '\n'

    while bytes_written != 32 and off != len(self.inst_bytes):
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
  top_errors = {}
  while True:
    (asm, next_pos) = hex_instructions.GenAsmBundle(start_pos)
    assert(asm)
    # Collect erroreous offsets, stub them out, repeat until no error.
    while True:
      asmfile = os.path.basename(hexfile[:-4]) + ('_part%03d.s' % runs)
      asmfile = os.path.join(tmp, asmfile)
      (status, err_offset) = CheckAsm(asm, asmfile, gas, validator)
      runs += 1
      if not status:
        return False
      if err_offset == None:
        break
      print 'start_pos: 0x%x, err_offset: 0x%x, global_err_offset: 0x%x, asmfile: %s' % (
          start_pos,
          err_offset,
          err_offset + start_pos,
          asmfile)
      if not hex_instructions.HasOffset(start_pos + err_offset):
        PrintError('validator returned error on offset that is not a ' +
                   'start of an instruction: 0x%x' % (start_pos + err_offset))
        return False
      if hex_instructions.InstInBundle(err_offset, start_pos):
        top_errors[start_pos + err_offset] = ['validation error']
        hex_instructions.StuboutInst(start_pos + err_offset)
        (asm, unused_next_pos) = hex_instructions.GenAsmBundle(start_pos)
      else:
        # If the instruction crosses the bundle boundary, we check if it gets
        # validated as placed at address 0mod32, then go processing the next
        # bundle.  Stubout the instruction if necessary.
        top_errors[start_pos + err_offset] = ['crosses boundary']
        (asm, unused_next_pos) = (
            hex_instructions.GenAsmBundle(start_pos + err_offset))
        assert(asm)
        asmfile = os.path.basename(hexfile[:-4]) + ('_part%03d.s' % runs)
        asmfile = os.path.join(tmp, asmfile)
        (status, boundary_err_offset) = CheckAsm(asm, asmfile, gas, validator)
        runs += 1
        if not status:
          return False
        if boundary_err_offset != None:
          if hex_instructions.OffsetBelongsToInst(start_pos + err_offset + boundary_err_offset,
                                                  start_pos + err_offset):
            top_errors[start_pos + err_offset].append('validation error')
        hex_instructions.StuboutInst(start_pos + err_offset)
        print 'stubout offset: 0x%x' % (start_pos + err_offset)
        break

    if next_pos == 0:
      # TODO: next_pos -> has_next
      break
    start_pos += 32

  # Compare the collected offsets with the golden file.
  if not CompareOffsets(tmp, top_errors, hexfile):
    return False
  return True


def Main():
  parser = optparse.OptionParser()
  parser.add_option(
      '-t', '--tests', dest='tests',
# reports error on instruction that follows the xchg esp, ebp, replacing it does not help
#      default='stack_regs',
#      default='mov-lea-rbp-bad-1',
#      default='mov-lea-rbp-bad-2',
#      default='mov-lea-rbp-bad-3',
#      default='mov-lea-rbp-bad-4',
#      default='mv_ebp_alone',
# the @ expansion:
#      default='call0',
#      default='call1',
#      default='call_long',
#      default='call_short',
#      default='jmp0',
#      default='jump_not_atomic',
#      default='jump_not_atomic_1',
#      default='jump_overflow',
#      default='jump_underflow',
#      default='mv_ebp_add_crossing',
#      default='return',
#      default='segment_aligned',
#      default='segment_not_aligned',
#      default='update-rsp',
      default='sse,legacy,rex_invalid,ud2,stosd67,mov-lea-rbp,valid_lea_store,mov-esi-nop-use,call-ex,data66prefix,maskmov_test,rip-relative,incno67,hlt,change-subregs,pop-rbp,invalid_base,prefix-single,prefix-3,call_not_aligned,add_rsp_r15,prefix-2,invalid_base_store,add_mult_prefix,segment_store,lea-rsp,inc67,extensions,mov_rbp_2_rsp,rip67,movsbw,sub-add-rsp,fs_use,cpuid,read_const_ptr,cmpxchg,add_cs_gs_prefix,mov-lea-rbp-bad-5,nacl_illegal,rep_tests,mov-lea-rsp,test_insts,valid_base_only,fpu,rdmsr,segment_assign,bad66,wrmsr,stosd,jump_atomic,movlps-ex,3DNow,bsf-mask,mv_ebp_add_rbp_r15,jmp-16,nops,ambig-segment,bt,sub-rsp,strings,mov_esp_add_rsp_r15,indirect_jmp_masked,movs_test,addrex,addrex2,bsr-mask,stosd-bad,indirect_jmp_not_masked,call_aligned,rex_not_last,invalid_width_index,jump_outside,x87,mmx,rbp67,push-memoff,AhNotSubRsp,call_not_aligned_16,valid_and_store,stosdno67,lea,dup-prefix,stubseq,lea-add-rsp',
#      default='sse',
#      default='nops',
#      default='bt',
#      default='legacy',
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
