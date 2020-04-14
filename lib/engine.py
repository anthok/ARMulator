__author__ = "Kyle Anthony"

import os
import sys
import pdb
import logging

try:
  from unicorn import *
  from unicorn.arm_const import *
  from capstone import *
  from lib import configloader 
  from colorama import Fore, Back, Style
  import hexdump
except ImportError as i_err:
  logging.error("[-] Error, could not import %s" % str(i_err))


# callback for tracing instructions
def dump_register_state(mu, full_dbg=True):
  '''
  Purpose: dump all register states
  Parameters: [mu] Unicorn variable
              [full_dbg] logging.info additional arm registers (R8-R12) 
              and special registers
  Return: N/A
  '''
  r0 = mu.reg_read(UC_ARM_REG_R0)
  r1 = mu.reg_read(UC_ARM_REG_R1)
  r2 = mu.reg_read(UC_ARM_REG_R2)
  r3 = mu.reg_read(UC_ARM_REG_R3)
  r4 = mu.reg_read(UC_ARM_REG_R4)
  r5 = mu.reg_read(UC_ARM_REG_R5)
  r6 = mu.reg_read(UC_ARM_REG_R6)
  r7 = mu.reg_read(UC_ARM_REG_R7)
  r8 = mu.reg_read(UC_ARM_REG_R8)
  r9 = mu.reg_read(UC_ARM_REG_R9)
  r10 = mu.reg_read(UC_ARM_REG_R10)
  r11 = mu.reg_read(UC_ARM_REG_R11)
  r12 = mu.reg_read(UC_ARM_REG_R12)
  sp = mu.reg_read(UC_ARM_REG_SP)
  pc = mu.reg_read(UC_ARM_REG_PC)

  print("R0 = 0x%x" %r0)
  print("R1 = 0x%x" %r1)
  print("R2 = 0x%x" %r2)
  print("R3 = 0x%x" %r3)
  print("R4 = 0x%x" %r4)
  print("R5 = 0x%x" %r5)
  print("R6 = 0x%x" %r6)
  print("R7 = 0x%x" %r7)
  if full_dbg:
    print("R8 = 0x%x" %r8)
    print("R9 = 0x%x" %r9)
    print("R10 = 0x%x" %r10)
    print("R11 = 0x%x" %r11)
    print("R12 = 0x%x" %r12)

  print("SP = 0x%x" %sp)
  print("PC = 0x%x" %pc)

def hook_code(mu, address, size, user_data):
  '''
  Purpose: Emulate user provided ARM code.
  '''
  try:
    print(Fore.YELLOW + ">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
    print(Style.RESET_ALL)


    pc = address # set program counter
    cur_bytes = mu.mem_read(pc-8, size*6)

    cur_bytes_str = ""
    for char in cur_bytes:
      cur_bytes_str += "{:02x}".format(char,'x')
      cur_bytes_str += " "

    # print(">>> %s" % cur_bytes_str)
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    for index,i in enumerate(md.disasm(cur_bytes, address-8)):
      if index == 2:
        print(Fore.GREEN + "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str) + Style.RESET_ALL)
      else:
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

    print("\n")


  except Exception as e:
    # logging.error("Error in hook_code: " + e)
    sys.exit(1)

  dump_register_state(mu)

  try:
    while True:
      command = input("q,s,any key or dump <0xaddr> <0xsize>\n: ")
      if "dump" in command:
        args = command.split(" ")
        dump_bytes = mu.mem_read(int(args[1],16), int(args[2],16))
        # dump_bytes_str = ""

        # counter = 1
        # for char in dump_bytes:
        #   dump_bytes_str += "{:02x}".format(char,'x')
        #   dump_bytes_str += " "
        #   if counter % 8 == 0:
        #     dump_bytes_str += "\n"
        #   counter += 1

        print(Fore.RED)
        hexdump.hexdump(dump_bytes)
        print(Style.RESET_ALL)
      elif "q" in command:
        sys.exit(1)
      elif "s" in command:
        mu.reg_write(UC_ARM_REG_PC, pc + 4)
        os.system('clear')
        break
      else:
        os.system('clear')
        break


  except KeyboardInterrupt as e:
    sys.exit(1)
    
class EmulationEngine(object):
  '''
  EmulationEngine class responsible for core emulation logic
  '''

  def __init__(self, CODE, CONFIG):
    self.EXEC_CODE = CODE
    self.ENGINE_CONFIG = CONFIG
    self.mu = None
    self.RAMDUMP = None

    if os.path.exists(self.ENGINE_CONFIG.ram_dump):
      with open(self.ENGINE_CONFIG.ram_dump, 'rb') as fh:
        self.RAMDUMP = fh.read()

    self.initialize_engine()

  def initialize_engine(self):

    LOAD_ADDRESS = self.ENGINE_CONFIG.load_address
    RAM_ADDRESS = self.ENGINE_CONFIG.ram_address
    STACK_ADDRESS = 0x7fff0000

    LOWER_LOAD_ADDR =  LOAD_ADDRESS & 0xfffff000
    LOAD_ADDRESS_OFFSET = LOAD_ADDRESS - LOWER_LOAD_ADDR

    LOWER_RAM_ADDR =  RAM_ADDRESS & 0xfffff000
    RAM_ADDRESS_OFFSET = RAM_ADDRESS - LOWER_RAM_ADDR

    logging.debug('Rounding LOAD_ADDRESS:{} to lower page {}, offset of {}' \
          .format(str(hex(LOAD_ADDRESS)), 
                  str(hex(LOWER_LOAD_ADDR)),
                  str(hex(LOAD_ADDRESS_OFFSET))))

    logging.debug('Rounding RAM_ADDRESS:{} to lower page {}, offset of {}' \
          .format(str(hex(RAM_ADDRESS)), 
                  str(hex(LOWER_RAM_ADDR)),
                  str(hex(RAM_ADDRESS_OFFSET))))

    if self.ENGINE_CONFIG.arch == "arm":
      # Initialize emulator in ARM32 mode
      self.mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    else:
      logging.error("Other architectures are currently unimplemented")
      sys.exit(1)

    try:
      # pdb.set_trace()
      # map 6MB memory for this emulation, code, stack, ram
      self.mu.mem_map(LOWER_LOAD_ADDR, 2 * 1024 * 1024)
      self.mu.mem_map(STACK_ADDRESS, 2 * 1024 * 1024)

      # check if memory ranges overlap
      if not(LOWER_LOAD_ADDR <= LOWER_RAM_ADDR <= (LOWER_LOAD_ADDR + (2 * 1024 * 1024))):
        logging.info("Memory ranges don't overlap, allocating space")
        self.mu.mem_map(LOWER_RAM_ADDR, 2 * 1024 * 1024)

      # write machine code to be emulated to memory
      self.mu.mem_write(LOAD_ADDRESS , self.EXEC_CODE)
      if self.RAMDUMP:
        self.mu.mem_write(RAM_ADDRESS , self.RAMDUMP)



      # initialize machine registers
      self.mu.reg_write(UC_ARM_REG_R0,   self.ENGINE_CONFIG.reg_arm_r0)
      self.mu.reg_write(UC_ARM_REG_R1,   self.ENGINE_CONFIG.reg_arm_r1)
      self.mu.reg_write(UC_ARM_REG_R2,   self.ENGINE_CONFIG.reg_arm_r2)
      self.mu.reg_write(UC_ARM_REG_R3,   self.ENGINE_CONFIG.reg_arm_r3)
      self.mu.reg_write(UC_ARM_REG_R4,   self.ENGINE_CONFIG.reg_arm_r4)
      self.mu.reg_write(UC_ARM_REG_R5,   self.ENGINE_CONFIG.reg_arm_r5)
      self.mu.reg_write(UC_ARM_REG_R6,   self.ENGINE_CONFIG.reg_arm_r6)
      self.mu.reg_write(UC_ARM_REG_R7,   self.ENGINE_CONFIG.reg_arm_r7)
      self.mu.reg_write(UC_ARM_REG_R8,   self.ENGINE_CONFIG.reg_arm_r8)
      self.mu.reg_write(UC_ARM_REG_R9,   self.ENGINE_CONFIG.reg_arm_r9)
      self.mu.reg_write(UC_ARM_REG_R10,  self.ENGINE_CONFIG.reg_arm_r10)
      self.mu.reg_write(UC_ARM_REG_R11,  self.ENGINE_CONFIG.reg_arm_r11)
      self.mu.reg_write(UC_ARM_REG_R12,  self.ENGINE_CONFIG.reg_arm_r12)
      self.mu.reg_write(UC_ARM_REG_LR,   self.ENGINE_CONFIG.reg_arm_lr)
      self.mu.reg_write(UC_ARM_REG_SP,   STACK_ADDRESS + (2 * 1024 * 1024))
      self.mu.reg_write(UC_ARM_REG_PC,   self.ENGINE_CONFIG.reg_arm_pc)
      self.mu.reg_write(UC_ARM_REG_APSR, 0xFFFFFFFF) #All application flags turned on

    except UcError as e:
      logging.error("initialize_engine: %s" % e)
      sys.exit()




  def emulate(self):
    logging.info("Starting up the ARMULATOR")
    os.system('clear')

    try:
      self.mu.hook_add(UC_HOOK_CODE, hook_code)

      # emulate code in infinite time & unlimited instructions
      self.mu.emu_start(self.ENGINE_CONFIG.reg_arm_pc, self.ENGINE_CONFIG.load_address + len(self.EXEC_CODE))
      logging.info("Emulation done...")

    except UcError as e:
      logging.error("emulate: %s" % e)

