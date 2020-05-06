import capstone
import io
import keystone
import os
import re

from . import analyze

__doc__ = "instruction de/serialization"

def pload(path, sections = None, text = False):
    """
    load `BaseInstructionIO` instances corresponding to various sections within
    an object file

    sections are of the form `{name: base}`

    output is of the form
        ```
        {
            extent (section or segment): {
                "base": base,
                "extent": analyze.CodeSegment,
                "instructions": capstone.Cs
            }
        }
        ```
    """
    baseiio = AssemblyIO if text else MachineCodeIO

    with open(path, "rb") as fp:
        binary = analyze.Binary(fp.read())
    sections = dict(sections) if isinstance(sections, dict) else {".text": None}###############################################################is the name preceded with '.'????
    sections = {k: {"base": v} for k, v in sections.items()}

    for extent in binary.executable_sections:
        base = sections[extent.name] \
            if isinstance(sections.get(extent.name, None), int) \
            else extent.base
        sections[extent.name] = {
            "base": base
            "extent": extent,
            "instructions": baseiio.load(io.StringIO(extent.raw), binary.GET ISA, base)#############################################ISA?
        }
    return filter(lambda n: isinstance(sections[n], dict), sections)

class BaseInstructionIO:
    """instruction de/serialization"""

    @staticmethod
    def dump(instructions, isa, fp):
        """dump instructions to a file"""
        raise NotImplementedError()

    @staticmethod
    def load(fp, isa):
        """load instructions from a file"""
        raise NotImplementedError()

class AssemblyIO(BaseInstructionIO):
    """assembly serialization"""

    @staticmethod
    def dump(instructions, isa, fp):
        """dump assembly to a file"""
        return keystone.Ks(isa["keystone"]).asm(instructions)

    @staticmethod
    def load(fp, isa, offset = 0):
        """load assembly from a file based on an ISA"""
        # first, assemble

        s = io.StringIO()
        AssemblyIO.dump(fp.read(), s)
        s.seek(0, os.SEEK_SET)
        return MachineCodeIO.load(s, isa, offset)

class MachineCodeIO(BaseInstructionIO):
    """machine code serialization"""

    @staticmethod
    def dump(instructions, isa, fp):
        """dump machine code to a file"""
        return AssemblyIO.dump(b';'.join((i.bytes for i in instructions)), isa,
            fp)

    @staticmethod
    def load(fp, isa, offset = 0):
        """load machine code from a file based on an ISA"""
        return capstone.Cs(isa["capstone"]).disasm(fp.read(), offset)

