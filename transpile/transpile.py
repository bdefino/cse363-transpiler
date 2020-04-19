import capstone

from . import iio, verbosity

class Transpiler:
    """transpilation base"""

    def __init__(self, target, all_permutations = False, recurse = False, verbosity = None):
        self.target = target
        self.instructions = []
    
    def __call__(self, *objs):
        """transpile the target from a series of objects"""
        raise NotImplementedError()##################################################

    def parse_instructions(self):
      """"""
      raise NotImplementedError()####################################################

class Gadget:
  """Gadget Object"""

  def __init__(self, binary):
    self.binary = binary


  def get_gadget(self, instruction):
    """"""
    pass
