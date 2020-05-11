import capstone
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

__doc__ = "instruction de/serialization"#############auto-correlate upon calls; add pload to BaseInstructionIO spec

class BaseInstructionIO:
    """instruction de/serialization"""

    @staticmethod
    def dump(fp, instructions, isa):
        """dump instructions (`capstone.CsInsn/bytes/str`s) to a file"""
        return keystone.Ks(isa["keystone"]["arch"],
            isa["keystone"]["endianness"] + isa["keystone"]["mode"]).asm(
                instructions)

    @staticmethod
    def load(fp, isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        raise NotImplementedError()

    @staticmethod
    def ploadall(path, isa, sections = None):
        """
        load all executable sections at a path

        input sections are of the form `{name: base}`

        output is of the form
            ```
            {
                extent (section or segment): {
                    "base": base,
                    "extent": analyze.CodeSegment/bytes/str,
                    "instructions": iterable of capstone.CsInsn
                },
                ....
            }
            ```
        """
        raise NotImplementedError()

class AssemblyIO(BaseInstructionIO):
    """assembly deserialization"""

    @staticmethod
    def load(fp, isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        # first, assemble

        s = io.StringIO()
        BaseInstructionIO.dump(s, fp.read(), isa)
        s.seek(0, os.SEEK_SET)

        # disassemble

        return MachineCodeIO.load(s, isa, offset)

    @staticmethod
    def pload(path, isa, offset = 0):
        """
        load ~~all~~ A SINGLE executable section~~s~~ at a path

        input sections are of the form `{name: base}`

        output is of the form
            ```
            {
                extent (section or segment): {
                    "base": base,
                    "extent": analyze.CodeSegment/bytes/str,
                    "instructions": iterable of capstone.CsInsn
                },
                ....
            }
            ```
        """
        with open(path) as fp:
            return AssemblyIO.load(fp, isa, offset)

class MachineCodeIO(AssemblyIO):
    """machine code deserialization"""

    @staticmethod
    def load(fp, isa, offset = 0):
        """load `capstone.CsInsn`s from a file (given an offset)"""
        return capstone.Cs(isa["capstone"]["arch"],
            isa["capstone"]["endianness"] + isa["capstone"]["mode"]).disasm(
                fp.read(), offset)

    @staticmethod
    def ploadall(path, sections = None):
        """
        load all executable sections at a path

        input sections are of the form `{name: base}`

        output is of the form
            ```
            {
                extent (section or segment): {
                    "base": base,
                    "extent": analyze.CodeSegment/bytes/str,
                    "instructions": iterable of capstone.CsInsn
                },
                ....
            }
            ```
        """

        # load the binary

        with open(path, "rb") as fp:
            binary = analyze.Binary(fp.read())
        print({k: getattr(binary, k) for k in ("arch", "endianess", "mode")})
        # compute the complete ISA

        _isa = isa.correlate({
            "capstone": {
                "arch": binary.arch,
                "endianness": binary.endianess,
                "mode": binary.mode
            }
        })

        # load sections

        sections = dict(sections) if isinstance(sections, dict) \
            else {".text": None}
        sections = {k: {"base": v} for k, v in sections.items()}

        for extent in binary.executable_sections:
            base = sections[extent.name] \
                if isinstance(sections.get(extent.name, None), int) \
                else extent.addr
            sections[extent.name] = {
                "base": base,
                "extent": extent,
                "instructions": MachineCodeIO.load(
                    io.BytesIO(extent.binary_arr), _isa, base),
                "isa": _isa
            }

        # filter out unmatched sections

        return {k: v for k, v in sections.items() if len(v.keys()) > 1}

if __name__ == "__main__":
    # test loading from a binary

    print(MachineCodeIO.ploadall("../linux_32"))
    print(AssemblyIO.pload("../setx.S", {
        "arch": capstone.CS_ARCH_X86,
        "endianness": capstone.CS_MODE_LITTLE_ENDIAN,
        "mode": capstone.CS_MODE_32
        }))

