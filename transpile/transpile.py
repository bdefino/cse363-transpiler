import capstone

try:
    from . import gadget, iio, verbosity
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import gadget
    import iio
    import verbosity

class Transpiler:
    """transpilation base"""

    def __init__(self, target, all_permutations = False, recurse = False, verbosity = None):
        self.target = target # `capstone.CsInsn`s

    def __call__(self, *objs):
        """
        transpile the target from a series of objects

        where each object is of the form `(path, {section: base})`
        """
        # load objects

        objs = [iio.pload(o) for o in objs] # load all objects from disk

        if not len(set((o.isa for o in objs))) == 1:
            raise TypeError("ISA mismatch (or no ISA)")

        # populate gadgets

        for o in objs:
            objs[o]["gadgets"] = Gadgets(obj["instructions"])

        # search for corresponding gadgets

        ################################################################################

        # build stack frames

        raise NotImplementedError()##################################################

class Gadget:
  """Gadget Object"""

  def __init__(self, binary):
    self.binary = binary

  def get_gadget(self, instruction):
    """"""
    pass

