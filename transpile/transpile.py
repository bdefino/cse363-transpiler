import capstone
import io
import itertools
import re
import struct

try:
    from . import gadget, iio
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import gadget
    import iio


class Transpiler:
    """transpilation base"""

    def __init__(self, target, all_permutations=False, recurse=False):
        self.target = target  # `capstone.CsInsn`s

    def __call__(self, *objs):
        """
        transpile the target from a series of objects

        where each object is of the form `(path, {section: base})`
        """
        # load objects

        objs = [iio.pload(o) for o in objs]  # load all objects from disk

        if Transpiler._isa_mismatch():
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

        if Transpiler._isa_mismatch(*objs):
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
        for g in gadgetss:
            gadget = g.search(pattern)

            if g is not None:
                return gadget
        return None

    @staticmethod
    def _inc_reg_n(reg, n=0, *gadgetss):
        """incrementally fill a register"""
        # zero out the register

        chain = [Transpiler._first_matching_gadget("xor %s, %s" % (reg, reg),
                                                   *gadgetss)]

        # fill the register

        gadget = Transpiler._first_matching_gadget(
            ("dec %s" if n < 0 else "inc %s") % reg, *gadgetss)
        increment = -1 if n < 0 else 1

        while n:
            chain.append(gadget)
            n -= increment
        return chain

    @staticmethod
    def _isa_mismatch(*objs):
        """
        return whether there's a mismatch between the ISAs of extents across a
        collection of objects
        """
        print(objs)
        print(list(itertools.chain([[e["isa"] for e in o] for o in objs])))
        return len(set(itertools.chain([[e["isa"] for e in o]
            for o in objs]))) > 1

    @staticmethod
    def _reg_assign(*gadgetss, **regs):
        """
        return a chain for assigning a value to a register;
        these values MAY include miscellaneous types:
        which should be interpreted as REGISTER CONTENTS
        (endianness to be determined by the caller)
        """

        # attempt to match (sub)permutations

        chain = []
        matched = {}
        nregs = len(regs)
        unmatched = regs.clone()

        while nregs > 0:
            for perm in itertools.permutations(unmatched.keys(), nregs):
                pattern = ';'.join(["pop " + r for r in perm] + ["ret"])
                gadget = Transpiler._first_matching_gadget(pattern, *gadgetss)

                if gadget:
                    for reg in perm:
                        matched[reg] = gadget
                        del unmatched[reg]
                    nregs -= len(perm)
            nregs -= 1

        # populate matched registers

        for reg, gadget in matched.items():
            chain.append(gadget[0])
            chain.append(regs[reg])

        # populate unmatched registers incrementally

        for reg, n in unmatched.items():
            subchain = Transpiler._inc_reg_n(reg, n, *gadgets)

            if not subchain:
                return
            chain += subchain
        return chain

    @staticmethod
    def mprotect_pop_reg_combo(a, b, c, d, *gadgetss):
        """
        generate rop chain to pop a value from the payload to regs
        [eax, ebx, ecx, edx]
        in any combination
        """
        chain = []
        reg_d = {"eax": None,
                 "ebx": None,
                 "ecx": None,
                 "edx": None}

        # load the pool

        # check for single pop
        for c in POP_REG_COMBO_POOL["single"]:
            for g in gadgetss:
                gadget = g.search(c)
                if gadget:
                    re_output = re.findall("e[a-d]x", gadget[1])
                    if re_output:
                        reg_d[re_output[0]] = gadget

        # check for double pop
        for c in POP_REG_COMBO_POOL["double"]:
            for g in gadgetss:
                gadget = g.search(c)
                if gadget:
                    re_output = re.findall("e[a-d]x", gadget[1])
                    if re_output:
                        for reg in re_output:
                            reg_d[reg] = gadget

        # check for triple pop
        for c in POP_REG_COMBO_POOL["triple"]:
            for g in gadgetss:
                gadget = g.search(c)
                if gadget:
                    re_output = re.findall("e[a-d]x", gadget[1])
                    if re_output:
                        for reg in re_output:
                            reg_d[reg] = gadget

        # check for quad pop
        for c in POP_REG_COMBO_POOL["quad"]:
            for g in gadgetss:
                gadget = g.search(c)
                if gadget:
                    re_output = re.findall("e[a-d]x", gadget[1])
                    if re_output:
                        for reg in re_output:
                            reg_d[reg] = gadget

        # check for odd ones out
        if not all(reg_d.values()):
            raise ValueError("pop reg failed")

        # push all reg_d values in a set
        s = set()
        for g in reg_d.items():
            s.add(g)

        ##################################################################
        # need endianess; default little x86
        for g in s:
            # check the gagdet
            chain += list(g[0])
            lst = re.findall("e[a-d]x", g[1])
            for e in lst:
                if e == "eax":
                    chain += list(struct.pack("<I", a))
                if e == "ebx":
                    chain += list(struct.pack("<I", b))
                if e == "ecx":
                    chain += list(struct.pack("<I", c))
                if e == "edx":
                    chain += list(struct.pack("<I", d))

        return chain

    @staticmethod
    def _pop_reg(reg, val, *gadgetss):
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
        if Transpiler._isa_mismatch(*objs):
            raise TypeError("ISA mismatch")
        # per-ISA discrimination
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
        # Mprotect Pop method
        try:
            chain = Transpiler.mprotect_pop_reg_combo(
                125,
                kwargs["rop"],
                kwargs["buflen"],
                7,
                *gadgetss)
        except ValueError:
            # pop method failed; do other

            # `mov eax, (MPROTECT)`
            chain += list(Transpiler._mov_reg_n("eax", 125, *gadgetss))

            # `mov ebx, (ROP)`

            chain += list(Transpiler._mov_reg_n("ebx", kwargs["rop"],
                                                *gadgetss))
            # `mov ecx, (BUFLEN)`

            chain += list(Transpiler._mov_reg_n("ecx", kwargs["buflen"],
                                                *gadgetss))
            # `mov edx, (PROT_EXEC | PROT_READ | PROT_WRITE)`

            chain += list(Transpiler._mov_reg_n("edx", 7, *gadgetss))
        finally:
            # `int 0x80`

            chain.append(Transpiler._first_matching_gadget(
                "int 0x80", *gadgetss))
            return b"".join(chain)


if __name__ == "__main__":
    # localized: `os` and `sys` were already imported;
    # generate an `mprotect` chain for x86-32 Linux

    sys.argv += ["../linux_32"]
    chain = Transpiler.chain("mprotect", buf=0xEEEEEEEE, buflen=0xFFFFFFFF,
                             rop=-0x1, *[iio.MachineCodeIO.ploadall(p) for p in sys.argv[1:]])

    with os.fdopen(sys.stdout.fileno(), "wb") as fp:
        fp.write(chain)


POP_REG_COMBO_POOL = {
    "single": [
        "pop eax; ret;",
        "pop ebx; ret;",
        "pop ecx; ret;",
        "pop edx; ret;"
    ],
    "double": [
        "pop eax; pop ebx; ret;",
        "pop eax; pop ecx; ret;",
        "pop eax; pop edx; ret;",
        "pop ebx; pop eax; ret;",
        "pop ebx; pop ecx; ret;",
        "pop ebx; pop edx; ret;",
        "pop ecx; pop eax; ret;",
        "pop ecx; pop ebx; ret;",
        "pop ecx; pop edx; ret;",
        "pop edx; pop eax; ret;",
        "pop edx; pop ebx; ret;",
        "pop edx; pop ecx; ret;"
    ],
    "triple": [
        "pop eax; pop ebx; pop ecx; ret;",
        "pop eax; pop ebx; pop edx; ret;",
        "pop eax; pop ecx; pop ebx; ret;",
        "pop eax; pop ecx; pop edx; ret;",
        "pop eax; pop edx; pop ecx; ret;",
        "pop eax; pop edx; pop ebx; ret;",
        "pop ebx; pop ecx; pop edx; ret;",
        "pop ebx; pop ecx; pop eax; ret;",
        "pop ebx; pop edx; pop eax; ret;",
        "pop ebx; pop edx; pop ecx; ret;",
        "pop ebx; pop eax; pop ecx; ret;",
        "pop ebx; pop eax; pop edx; ret;",
        "pop ecx; pop edx; pop eax; ret;",
        "pop ecx; pop edx; pop ebx; ret;",
        "pop ecx; pop eax; pop ebx; ret;",
        "pop ecx; pop eax; pop edx; ret;",
        "pop ecx; pop ebx; pop edx; ret;",
        "pop ecx; pop ebx; pop eax; ret;",
        "pop edx; pop eax; pop ebx; ret;",
        "pop edx; pop eax; pop ecx; ret;",
        "pop edx; pop ebx; pop ecx; ret;",
        "pop edx; pop ebx; pop eax; ret;",
        "pop edx; pop ecx; pop ebx; ret;",
        "pop edx; pop ecx; pop eax; ret;"
    ],
    "quad": [
        "pop eax; pop ebx; pop ecx; pop edx; ret;",
        "pop eax; pop ebx; pop edx; pop ecx; ret;",
        "pop eax; pop ecx; pop ebx; pop edx; ret;",
        "pop eax; pop ecx; pop edx; pop ebx; ret;",
        "pop eax; pop edx; pop ebx; pop ecx; ret;",
        "pop eax; pop edx; pop ecx; pop ebx; ret;",
        "pop ebx; pop eax; pop ecx; pop edx; ret;",
        "pop ebx; pop eax; pop edx; pop ecx; ret;",
        "pop ebx; pop edx; pop eax; pop ecx; ret;",
        "pop ebx; pop edx; pop ecx; pop eax; ret;",
        "pop ebx; pop ecx; pop eax; pop edx; ret;",
        "pop ebx; pop ecx; pop edx; pop eax; ret;",
        "pop ecx; pop eax; pop ebx; pop edx; ret;",
        "pop ecx; pop eax; pop edx; pop ebx; ret;",
        "pop ecx; pop ebx; pop eax; pop edx; ret;",
        "pop ecx; pop ebx; pop edx; pop eax; ret;",
        "pop ecx; pop edx; pop eax; pop ebx; ret;",
        "pop ecx; pop edx; pop ebx; pop eax; ret;",
        "pop edx; pop eax; pop ebx; pop ecx; ret;",
        "pop edx; pop eax; pop ecx; pop ebx; ret;",
        "pop edx; pop ebx; pop eax; pop ecx; ret;",
        "pop edx; pop ebx; pop ecx; pop eax; ret;",
        "pop edx; pop ecx; pop eax; pop ebx; ret;",
        "pop edx; pop ecx; pop ebx; pop eax; ret;"
    ]
}
