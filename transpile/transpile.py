import capstone
import copy
import io
import itertools
import re
import struct
import traceback

try:
    from . import gadget, iio, isa
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import gadget
    import iio
    import isa

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

        gadgetss = set()

        for o in objs:
            for e in o.values():
                e["gadgets"] = gadget.Gadgets(o["instructions"])
                gadgetss.add(e["gadgets"])

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
        _isa = None

        for o in objs:
            for e in o.values():
                if "isa" in e:
                    _isa = e["isa"]
                    break

            if _isa is not None:
                break

        if _isa is None:
            raise ValueError("no ISA")
        _isa = isa.correlate(copy.deepcopy(_isa))

        if which in chains:
            print("Generating the \"%s\" chain..." % which)
            chain = chains[which](*objs, **kwargs)

            if chain is None:
                print("Failed!")
                return
            print("Packing the chain...")
            packer = '>' if _isa["capstone"]["endianness"] \
                == capstone.CS_MODE_BIG_ENDIAN else '<'
            packer += 'I' if _isa["capstone"]["mode"] == capstone.CS_MODE_32 \
                else 'L'

            for i, e in enumerate(chain):
                if isinstance(e, bytes):
                    continue
                else:
                    # treat as a machine word

                    chain[i] = struct.pack(packer, e)
            return b"".join(chain)
        raise ValueError("unsupported chain \"%s\"" % which)

    @staticmethod
    def _first_matching_gadget(pattern, *gadgetss):
        """
        return the first matching gadget from a list of `gadget.Gadgets`
        instances
        """
        for g in gadgetss:
            gadgets = g.search(pattern)

            if gadgets:
                addr, gadget = list(gadgets.items())[0]
                print("0x%.16x\t%s" % (addr, gadget))
                return addr
        return None

    @staticmethod
    def _inc_reg_n(reg, n=0, *gadgetss):
        """incrementally fill a register"""
        # zero out the register

        chain = [Transpiler._first_matching_gadget(
            "xor %s, %s;ret" % (reg, reg), *gadgetss)]

        # fill the register

        g = Transpiler._first_matching_gadget(
            "((add %s, -1)|(dec %s)|(sub %s, 1));ret" % (reg, reg, reg)
                if n < 0 else
                "((add %s, 1)|(inc %s)|(sub %s, -1));ret" % (reg, reg, reg),
            *gadgetss)

        if g is None:
            return
        print("\t(* %u)" % abs(n))
        increment = -1 if n < 0 else 1

        while n:
            chain.append(g)
            n -= increment
        return chain

    @staticmethod
    def _isa_mismatch(*objs):
        """
        return whether there's a mismatch between the ISAs of extents across a
        collection of objects
        """
        if not objs:
            return False
        isas = []

        for o in objs:
            for e in o:
                if "isa" in e:
                    isas.append(e["isa"])

        if not isas:
            return False

        for isa in isas[1:]:
            if not isa == isas[0]:
                return True
        return False

    @staticmethod
    def _reg_assign(*gadgetss, **regs):#########################################incorporate temporary registers
        """
        return a chain for assigning a value to a register;
        these values MAY include non-`bytes` values:
        which should be interpreted as REGISTER CONTENTS
        (endianness to be determined by the caller)
        """

        # attempt to match (sub)permutations of direct `pop REG`s

        chain = []
        direct = {} # `{ordered registers: gadget address}`
        nregs = len(regs)
        unmatched = set(regs.keys())

        while nregs > 0:
            matched_any = False

            for perm in itertools.permutations(unmatched, nregs):
                pattern = ';'.join(["pop " + r for r in perm] + ["ret"])
                pop = Transpiler._first_matching_gadget(pattern, *gadgetss)

                if pop is None:
                    continue

                for r in perm:
                    unmatched.remove(r)
                direct[tuple(perm)] = pop
                matched_any = True
                break

            if not matched_any:
                nregs -= 1
            nregs = min((len(unmatched), nregs))

        # attempt to indirectly assign via a combination
        # of `pop MATCHED` and `mov REG`

        pool = set(regs.keys()) # temp

        for u in set(unmatched):
            for p in set(pool): # copy
                # attempt to fully match `pop MATCHED; mov REG`

                if p == u:
                    continue

                pop_move = Transpiler._first_matching_gadget(
                    "pop %s;mov %s, %s;ret" % (p, u, p), *gadgetss)

                if pop_move:
                    chain += [pop_move, regs[u]]
                    pool.remove(p)
                    unmatched.remove(u)
                    break

                # attempt to match a composite load (via multiple gadgets)

                pop = Transpiler._first_matching_gadget("pop %s;ret" % p, *gadgetss)

                if pop is None:
                    break
                move = Transpiler._first_matching_gadget(
                    "mov %s, %s;ret" % (u, p), *gadgetss)

                if move is None:
                    break
                chain += [pop, regs[u], move]
                pool.remove(p)
                unmatched.remove(u)

        # populate directly-loadable registers

        for rs, pop in direct.items():
            # add gadget

            chain.append(pop)

            # add values

            for r in rs:
                chain.append(regs[r])

        # populate unmatched registers incrementally
        # (via `xor REG, REG;inc/dec REG;...`)

        for r in unmatched:
            subchain = Transpiler._inc_reg_n(r, regs[r], *gadgetss)

            if subchain is None:
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
        missing = []
        reg_d = {"eax": None,
                 "ebx": None,
                 "ecx": None,
                 "edx": None}

        # load the pool
        # gadgetss = all of the gadget form all binarys (Multiple gagdet objs)
        # g.search = searchs for gadgets in gadget objs
        # check for single pop

        for k, v in POP_REG_COMBO_POOL.items():
            for regex in v:
                gg = Transpiler._first_matching_gadget(regex, *gadgetss)
                if gg:
                    re_output = re.findall("e[a-d]x", regex)
                    if re_output:
                        for reg in re_output:
                            reg_d[reg] = (gg, regex)

        # push all reg_d values in a set
        s = set()
        for k, v in reg_d.items():
            if v:
                s.add(v)
            else:
                missing += [k]

        for g in s:
            # check the gagdet
            chain += [g[0]]
            lst = re.findall("e[a-d]x", g[1])
            for e in lst:
                if e == "eax":
                    chain += [a]
                if e == "ebx":
                    chain += [b]
                if e == "ecx":
                    chain += [c]
                if e == "edx":
                    chain += [d]

        return (chain, missing)

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

        ################################################################################

        for k in ("buf", "buflen", "rop"):
            if not k in kwargs:
                raise KeyError("expected \"%s\" in `kwargs`" % k)
            elif not isinstance(kwargs[k], int):
                raise KeyError(
                    "expected `kwargs[\"%s\"]` to be a positive integer" % k)

        # load all gadgets

        gadgetss = set()

        for o in objs:
            for no, e in o.items():
                print("Loading gadgets from object (extent \"%s\", offset %u)..." % no)
                e["gadgets"] = gadget.Gadgets(e["instructions"])
                gadgetss.add(e["gadgets"])

        # create chain

        print("Generating gadget chain...")
        chain = []
        ############################
        # Mprotect Pop method
        try:
            chain = Transpiler._reg_assign(eax=125, ebx=kwargs["buf"],
                                            ecx=kwargs["buflen"], edx=7, *gadgetss)
            """chain, missing = Transpiler.mprotect_pop_reg_combo(
                125,
                kwargs["buf"],
                kwargs["buflen"],
                7,
                *gadgetss)

            for m in missing:
                if m == "eax":
                    chain += Transpiler._inc_reg_n(m, 125, *gadgetss)
                if m == "ebx":
                    chain += Transpiler._inc_reg_n(m,
                                                    kwargs["buf"], *gadgetss)
                if m == "ecx":
                    chain += Transpiler._inc_reg_n(m,
                                                    kwargs["buflen"], *gadgetss)
                if m == "edx":
                    chain += Transpiler._inc_reg_n(m, 7, *gadgetss)
            # detect if full chain. If not,
            # use fallback methods to fill in the odd ones out"""
        except ValueError as e:
            traceback.print_exception(
                type(e), e, e.__traceback__, file=sys.stderr)

            # `mov eax, (MPROTECT)`
            # chain += list(Transpiler._inc_reg_n("eax", 125, *gadgetss))

            # # `mov ebx, (ROP)`

            # chain += list(Transpiler._inc_reg_n("ebx", kwargs["rop"],
            #                                     *gadgetss))
            # # `mov ecx, (BUFLEN)`

            # chain += list(Transpiler._inc_reg_n("ecx", kwargs["buflen"],
            #                                     *gadgetss))
            # # `mov edx, (PROT_EXEC | PROT_READ | PROT_WRITE)`

            # chain += list(Transpiler._inc_reg_n("edx", 7, *gadgetss))
        # `int 0x80`

        if chain is None:
            return chain
        chain.append(Transpiler._first_matching_gadget(
            "int 0x80", *gadgetss))

        if chain[-1] is None:
            return
        chain.append(kwargs["buf"])
        return chain


if __name__ == "__main__":
    # localized: `os` and `sys` were already imported;
    # generate an `mprotect` chain for x86-32 Linux

    sys.argv += ["../libc.so.6"]
    chain = Transpiler.chain("mprotect", buf=0x1, buflen=0x2,
                             rop=-0x1, *[iio.MachineCodeIO.ploadall(p) for p in sys.argv[1:]])

    with open("mprotect-chain", "wb") as fp:
        fp.write(chain)

