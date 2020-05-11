import capstone
import copy
import io
import keystone
import os
import re

try:
    from . import analyze, isa
except ImportError:
    import sys

    sys.path.append(os.path.realpath(__file__))

    import analyze
    import isa

__doc__ = "instruction de/serialization"

class BaseInstructionIO:
    """instruction de/serialization"""

    @staticmethod
    def dump(fp, instructions, _isa):
        """dump instructions (`capstone.CsInsn/bytes/str`s) to a file"""
        _isa = isa.correlate(copy.deepcopy(_isa))
        return keystone.Ks(_isa["keystone"]["arch"],
            _isa["keystone"]["endianness"] + _isa["keystone"]["mode"]).asm(
                instructions)

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        raise NotImplementedError()

    @staticmethod
    def pload(path, _isa, offset = 0):
        """
        load a single executable extent at a path

        input extents are of the form `{name: base}`

        output is of the form
            ```
            {
                "base": base,
                "extent": analyze.CodeSegment/bytes/str,
                "instructions": iterable of capstone.CsInsn,
                "isa": ISA
            }
            ```
        """

    @staticmethod
    def ploadall(path, _isa, extents = None):
        """
        load all executable extents at a path

        input extents are of the form `{name: base}`

        output is of the form
            ```
            {
                extent (extent or segment): {
                    "base": base,
                    "extent": analyze.CodeSegment/bytes/str,
                    "instructions": iterable of capstone.CsInsn,
                    "isa": ISA
                },
                ....
            }
            ```
        """
        raise NotImplementedError()

class AssemblyIO(BaseInstructionIO):
    """assembly deserialization"""

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        # first, assemble

        s = io.StringIO()
        BaseInstructionIO.dump(s, fp.read(), _isa)
        s.seek(0, os.SEEK_SET)

        # d_isassemble

        return MachineCodeIO.load(s, _isa, offset)

    @staticmethod
    def pload(path, _isa, offset = 0):
        """
        load a single executable extent at a path

        input extents are of the form `{name: base}`

        output is of the form
            ```
            {
                "base": base,
                "extent": analyze.CodeSegment/bytes/str,
                "instructions": iterable of capstone.CsInsn,
                "isa": ISA
            }
            ```
        """
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path) as fp:
            return AssemblyIO.load(fp, _isa, offset)

class MachineCodeIO(AssemblyIO):
    """machine code deserialization"""

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        _isa = isa.correlate(copy.deepcopy(_isa))
        return capstone.Cs(_isa["capstone"]["arch"],
            _isa["capstone"]["endianness"] + _isa["capstone"]["mode"]).d_isasm(
                fp.read(), offset)

    @staticmethod
    def pload(path, _isa, offset = 0):
        """
        load a single executable extent at a path

        input extents are of the form `{name: base}`

        output is of the form
            ```
            {
                "base": base,
                "extent": analyze.CodeSegment/bytes/str,
                "instructions": iterable of capstone.CsInsn,
                "isa": ISA
            }
            ```
        """
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path, "rb") as fp:
            extent = fp.read()
            fp.seek(0, os.SEEK_SET)
            return {
                "base": offset,
                "extent": extent,
                "instructions": MachineCodeIO.load(fp, _isa, offset),
                "isa": _isa
            }

    @staticmethod
    def ploadall(path, extents = None):
        """
        load all executable extents at a path

        input extents are of the form `{name: base}`

        output is of the form
            ```
            {
                extent (extent or segment): {
                    "base": base,
                    "extent": analyze.CodeSegment/bytes/str,
                    "instructions": iterable of capstone.CsInsn,
                    "isa": ISA
                },
                ....
            }
            ```
        """
        _isa = isa.correlate(_isa.clone())

        # load the binary

        with open(path, "rb") as fp:
            binary = analyze.Binary(fp.read())

        # compute the complete _isa

        _isa = isa.correlate({
            "capstone": {
                "arch": binary.arch,
                "endianness": binary.endianess,
                "mode": binary.mode
            }
        })

        # load extents

        extents = dict(extents) if isinstance(extents, dict) \
            else {".text": None}
        extents = {k: {"base": v} for k, v in extents.items()}

        for extent in binary.executable_extents:
            base = extents[extent.name] \
                if isinstance(extents.get(extent.name, None), int) \
                else extent.addr
            extents[extent.name] = {
                "base": base,
                "extent": extent,
                "instructions": MachineCodeIO.load(
                    io.BytesIO(extent.binary_arr), _isa, base),
                "isa": copy.deepcopy(_isa)
            }

        # filter out unmatched extents

        return {k: v for k, v in extents.items() if len(v.keys()) > 1}

if __name__ == "__main__":
    # test loading from a binary

    print(MachineCodeIO.ploadall("../linux_32"))
    print(AssemblyIO.pload("../setx.S", {
        "arch": capstone.CS_ARCH_X86,
        "endianness": capstone.CS_MODE_LITTLE_ENDIAN,
        "mode": capstone.CS_MODE_32
        }))

