class ARM_REG_STATE(object):
  def __init__(self):
    self.R0 = 0x0
    self.R1 = 0x0
    self.R2 = 0x0
    self.R3 = 0x0
    self.R4 = 0x0
    self.R5 = 0x0
    self.R6 = 0x0
    self.R7 = 0x0
    self.R8 = 0x0
    self.R9 = 0x0
    self.R10 = 0x0
    self.R11 = 0x0
    self.LR = 0x0
    self.SP = 0x0
    self.APSR = 0xFFFFFFFF

  def load_from_file(self, reg_state):
    pass



    