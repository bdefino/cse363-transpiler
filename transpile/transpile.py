import capstone
import io
import struct

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

    def __init__(self, target, all_permutations=False, recurse=False, verbosity=None):
        self.target = target  # `capstone.CsInsn`s

    def __call__(self, *objs):
        """
        transpile the target from a series of objects

        where each object is of the form `(path, {section: base})`
        """
        # load objects

        objs = [iio.pload(o) for o in objs]  # load all objects from disk

        if not all(([o.isa] == objs[:1] for o in objs[1:])):
            raise TypeError("ISA mismatch")

        # populate gadgets

        for o in objs:
            objs[o]["gadgets"] = gadget.Gadgets(o["instructions"])
        gadgetss = [o["gadgets"] for o in objs]

        # search for corresponding gadgets

        ################################################################################

        # build stack frames

        raise NotImplementedError()

    @staticmethod
    def chain(which="mprotect", *objs, **kwargs):
        """establish a predefined ROP chain"""
        chains = {"mprotect": Transpiler.mprotect}

        if not all(([o.isa] == objs[:1] for o in objs[1:])):
            raise TypeError("ISA mismatch")

        if which in chains:
            return chains[which](*objs, **kwargs)
        raise ValueError("unsupported chain \"%s\"" % which)

    @staticmethod
    def _first_matching_gadget(pattern, *gadgetss):
        """
        return the first matching gadget from a list of `gadget.Gadgets`
        instances
        """
        if not set((True for g in gadgetss)) == {True}:
            raise TypeError("expected `gadget.Gadgets` instances")

        for g in gadgetss:
            gadget = g.search(pattern)

            if g is not None:
                return gadget
        raise ValueError("no `%s` gadget" % pattern)

    @staticmethod
    def _mov_reg_n(reg, n=0, *gadgetss):
        """
        generate gadgets (from a collection of `gadget.Gadgets` instances) for
        moving a particular value into a register
        """
        if not set((True for g in gadgetss)) == {True}:
            raise TypeError("expected `gadget.Gadgets` instances")

        if not isinstance(n, int):
            raise TypeError("expected an integer")
        # zero out the register

        yield Transpiler._first_matching_gadget("xor %s, %s" % (reg, reg),
                                                *gadgetss)

        # fill the register

        gadget = Transpiler._first_matching_gadget(
            ("dec %s" if n < 0 else "inc %s") % reg, *gadgetss)
        increment = -1 if n < 0 else 1

        while n:
            yield gadget
            n -= increment

    @staticmethod
    def _pop_reg(reg, val, *gadgetss):
        if not set((True for g in gadgetss)) == {True}:
            raise TypeError("expected `gadget.Gadgets` instances")

        # convert val to bytes
        ##################################################################
        # need endianess; default little x86

        b_val = struct.pack("<I", val)

        # find reg
        gadget = Transpiler._first_matching_gadget(
            "pop %s" % reg, *gadgetss)

        # connect chain

        return [gadget, b_val]

    @staticmethod
    def mprotect(*objs, **kwargs):
        """
        generate an `mprotect` ROP chain
        (expects "buf", "buflen", and "rop" in `kwargs`)
        """
        if not all(([o.isa] == objs[:1] for o in objs[1:])):
            raise TypeError("ISA mismatch")
        #########################################################################################per-ISA discrimination
        for k, v in ("buf", "buflen", "rop"):
            if not "buf" in kwargs:
                raise KeyError("expected \"%s\" in `kwargs`" % k)
            elif not isinstance(v, int):
                raise KeyError(
                    "expected `kwargs[\"%s\"]` to be a positive integer" % k)

        # load all gadgets

        for o in objs:
            o["gadgets"] = gadget.Gadgets(o["instructions"])
        gadgetss = [o["gadgets"] for o in objs]

        # create chain

        chain = []
        ############################

        try:
            # `pop eax`
            chain += Transpiler._pop_reg("eax", 125, *gadgetss)
        except ValueError:
            # `mov eax, (MPROTECT)`

            chain += list(Transpiler._mov_reg_n("eax", 125, *gadgetss))

        try:
            # `pop ebx`
            chain += Transpiler._pop_reg("ebx", kwargs["rop"], *gadgetss)
        except ValueError:
            # `mov ebx, (ROP)`

            chain += list(Transpiler._mov_reg_n("ebx", kwargs["rop"],
                *gadgetss))

        try:
            # `pop ecx`
            chain += Transpiler._pop_reg("ecx", kwargs["buflen"], *gadgetss)
        except ValueError:
            # `mov ecx, (BUFLEN)`

            chain += list(Transpiler._mov_reg_n("ecx", kwargs["buflen"],
                                            *gadgetss))

        try:
            # `pop edx`
            chain += Transpiler._pop_reg("edx", 7, *gadgetss)
        except ValueError:
            # `mov edx, (PROT_EXEC | PROT_READ | PROT_WRITE)`

            chain += list(Transpiler._mov_reg_n("edx", 7, *gadgetss))

        # `int 0x80`

        chain.append(Transpiler._first_matching_gadget("int 0x80", *gadgetss))
        return b"".join(chain)


if __name__ == "__main__":
    # localized: `os` and `sys` were already imported;
    # generate an `mprotect` chain for x86-32 Linux

    chain = Transpiler.chain("mprotect", buf=0xEEEEEEEE, buflen=0xFFFFFFFF,
                             rop=-0x1, *[iio.pload(p) for p in sys.argv[1]])

    with os.fdopen(sys.stdout.fileno(), "wb") as fp:
        fp.write(chain)
