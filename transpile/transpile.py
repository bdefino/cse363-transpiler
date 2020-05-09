import capstone
import io

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
            objs[o]["gadgets"] = gadget.Gadgets(o["instructions"])

        # search for corresponding gadgets

        ################################################################################

        # build stack frames

        raise NotImplementedError()##################################################

    @staticmethod
    def chain(which = "mprotect", *objs, **kwargs):
        """establish a predefined ROP chain"""
        if not chain == "mprotect":
            raise ValueError("unsupported chain")

        for k, v in ("buf", "rop"):
            if not "buf" in kwargs:
                raise KeyError("expected \"%s\" in `kwargs`" % k)
            elif not isinstance(v, int):
                raise KeyError("expected `kwargs[\"%s\"]` to be an integer")

        # load all objects

        objs = [iio.pload(o) for o in objs]

        # load all gadgets

        gadgetss = []

        for o in objs:
            gadgetss.append(gadget.Gadgets(o["instructions"]))
            o["gadgets"] = gadgetss[-1]

        # create chain

        chain = []

        # `mov edx, 0x0007`

        chain += [g for g in Transpiler._mov_reg_n("edx", 7, *gadgetss)]

        # `mov ecx, (ROP - BUF)`

        chain += [g for g in Transpiler._mov_reg_n("ecx",
            kwargs["rop"] - kwargs["buf"], *gadgetss)]

        ##############
        raise NotImplementedError()##################################################

    @staticmethod
    def _first_matching_gadget(pattern, *gadgetss):
        """
        return the first matching gadget from a list of `gadget.Gadgets`
        instances
        """
        for g in gadgetss:
            gadget = g.search(pattern)

            if g is not None:
                return gadget

    @staticmethod
    def _mov_reg_n(reg, n = 0, *gadgetss):
        """
        generate gadgets (from a collection of `gadget.Gadgets` instances) for
        moving a particular value into a register
        """
        if not isinstance(n, int):
            raise TypeError("expected an integer")
        # zero out the register

        pattern = "xor %s, %s" % (reg, reg)
        xor_reg_reg = Transpiler._first_matching_gadget(pattern, *gadgetss)

        if xor_reg_reg is None:
            raise ValueError("no `%s` gadget" % pattern)
        yield xor_reg_reg

        # fill the register

        increment = 1 if n > 0 else -1
        pattern = "inc %s" % reg if n > 0 else "dec %s"
        gadget = Transpiler._first_matching_gadget(pattern, *gadgetss)

        if gadget is None:
            raise ValueError("no `%s` gadget" % pattern)

        while n:
            yield gadget
            n -= increment

