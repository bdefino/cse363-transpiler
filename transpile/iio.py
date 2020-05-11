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
    """
    instruction de/serialization

    files are always expected to be in byte mode

    instructions are formed in extents of the form:
        ```
        {
            "base": base,
            "extent": analyze.CodeSegment/bytes/str,
            "instructions": iterable of capstone.CsInsn,
            "isa": ISA
        }
        ```
    and multiple extents are grouped like so:
        `{name: extent}`
    """

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        raise NotImplementedError()

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load a single executable extent from a file"""
        raise NotImplementedError()

    @staticmethod
    def pdump(path, extent):
        """dump a single executable extent to a path"""
        raise NotImplementedError()

    @staticmethod
    def pload(path, _isa, offset = 0):
        """load a single executable extent at a path"""
        raise NotImplementedError()

    @staticmethod
    def ploadall(path, extents = None):
        """load all executable extents at a path"""
        raise NotImplementedError()

class AssemblyIO(BaseInstructionIO):
    """assembly deserialization"""

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        fp.write(b'\n'.join((bytes(i.mnemonic) for i in extent["instructions"])))

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load a single executable extent from a file"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        # first, assemble

        s = io.StringIO()
        _extent = fp.read()
        MachineCodeIO.dump(s, {"instructions": _extent, "isa": _isa})
        s.seek(0, os.SEEK_SET)

        # disassemble

        extent = MachineCodeIO.load(s, _isa, offset)
        extent["extent"] = _extent
        return extent

    @staticmethod
    def pdump(path, extent):
        """dump a single executable extent to a path"""
        with open(path, "wb") as fp:
            AssemblyIO.dump(fp, extent)

    @staticmethod
    def pload(path, _isa, offset = 0):
        """load a single executable extent at a path"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path, "rb") as fp:
            return AssemblyIO.load(fp, _isa, offset)

class MachineCodeIO(AssemblyIO):
    """machine code deserialization"""

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        _isa = isa.correlate(copy.deepcopy(extent["isa"]))
        return keystone.Ks(_isa["keystone"]["arch"],
            _isa["keystone"]["endianness"] + _isa["keystone"]["mode"]).asm(
                extent["instructions"])

    @staticmethod
    def load(fp, _isa, offset = 0):
        """load a single executable extent from a file"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        # need extent

        start = fp.tell()
        extent = fp.read()
        fp.seek(start)

        # load

        return {
                "base": offset,
                "extent": extent,
                "instructions": capstone.Cs(_isa["capstone"]["arch"],
                    _isa["capstone"]["endianness"]
                        + _isa["capstone"]["mode"]).disasm(fp.read(), offset),
                "isa": _isa
            }

    @staticmethod
    def pdump(path, extent):
        """load a single executable extent to a path"""
        _isa = isa.correlate(copy.deepcopy(extent["isa"]))

        with open(path, "wb") as fp:
            return MachineCodeIO.dump(fp, extent)

    @staticmethod
    def pload(path, _isa, offset = 0):
        """load a single executable extent at a path"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path, "rb") as fp:
            extent = fp.read()
            fp.seek(0, os.SEEK_SET)
            return {
                        "base":
                    }

    @staticmethod
    def ploadall(path, extents = None):
        """load all executable extents at a path"""

        # load the binary

        with open(path, "rb") as fp:
            binary = analyze.Binary(fp.read())

        # compute the complete _isa

        _isa = isa.correlate({
            "capstone": {
                "arch": binary.arch,
                "endianness": binary.endianess,
                "mode": binary.mode
            }})

        # load extents

        extents = dict(extents) if isinstance(extents, dict) \
            else {".text": None}
        extents = {k: {"base": v} for k, v in extents.items()}

        for extent in binary.executable_sections:
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

    compiled = MachineCodeIO.ploadall("../linux_32")
    print(compiled)
    source = AssemblyIO.pload("../x86-32-little.S", isa.parse("x86-32-little"))
    print(source)
    print([source["extent"]])

    with os.fdopen(sys.stdin.fileno(), "wb") as fp:
        AssemblyIO.dump(fp, source)
        MachineCodeIO.dump(fp, source)

