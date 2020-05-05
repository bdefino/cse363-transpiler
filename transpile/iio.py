import capstone
import io
import keystone
import os
import re

from . import analyze, header, isa

__doc__ = "instruction de/serialization"

def pload(path, sections = None, text = False):
    """
    load `BaseInstructionIO` instances corresponding to various sections within
    an object file
    """
    with open(path, "rb") as fp:
        binary = analyze.Binary(fp.read())
    sections = sections if isinstance(sections, dict) else {"text": {}}
    return [sections]########################################################################section headers (from analyze) -> `BaseInstructionIO` instances

class BaseInstructionIO:
    """instruction de/serialization"""

    @staticmethod
    def dump(instructions, fp):
        """dump instructions to a file"""
        raise NotImplementedError()

    @staticmethod
    def load(fp, isas):
        """load instructions from a file"""
        raise NotImplementedError()

class AssemblyIO(BaseInstructionIO):
    """assembly serialization"""

    @staticmethod
    def dump(instructions, fp):
        """dump assembly to a file"""
        if not isinstance(isas, str):
            raise TypeError("expected an ISA string")
        return keystone.Ks(*isa.parse(isas)["keystone"]).asm(instructions)

    @staticmethod
    def load(fp, isas, offset = 0):
        """load assembly from a file based on an ISA"""
        # first, assemble

        s = io.StringIO()
        AssemblyIO.dump(fp.read(), s)
        s.seek(0, os.SEEK_SET)
        return MachineCodeIO.load(s, isas, offset)

class MachineCodeIO(BaseInstructionIO):
    """machine code serialization"""

    @staticmethod
    def dump(instructions, fp):
        """dump machine code to a file"""
        return AssemblyIO.dump(b';'.join((i.bytes for i in instructions)), fp)

    @staticmethod
    def load(fp, isas, offset = 0):
        """load machine code from a file based on an ISA"""
        if not isinstance(isas, str):
            raise TypeError("expected an ISA string")
        return capstone.Cs(*isa.parse(isas)["capstone"]).disasm(fp.read(), offset)

