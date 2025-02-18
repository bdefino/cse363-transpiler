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
            "instructions": iterable of capstone.CsInsn,
            "isa": ISA,
            "offset": offset from the base (for variable-length ISAs)
        }
        ```
    and multiple extents are grouped like so:
        `{(name, offset): extent}`
    """

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        raise NotImplementedError()

    @staticmethod
    def load(fp, _isa, base=0, offset = 0):
        """load a single executable extent from a file"""
        raise NotImplementedError()

    @staticmethod
    def loadall(fp, base = 0, extents=None):
        """load all executable extents from a file"""
        raise NotImplementedError()

    @staticmethod
    def pdump(path, extent):
        """dump a single executable extent to a path"""
        raise NotImplementedError()

    @staticmethod
    def pload(path, _isa, base=0, offset = 0):
        """load a single executable extent at a path"""
        raise NotImplementedError()

    @staticmethod
    def ploadall(path, base = 0, extents=None):
        """load all executable extents at a path"""
        raise NotImplementedError()


class AssemblyIO(BaseInstructionIO):
    """assembly de/serialization"""

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        for i in extent["instructions"]:
            fp.write(b"%b %b\n" % tuple((s.encode("ascii") for s in (i.mnemonic, i.op_str))))

    @staticmethod
    def load(fp, _isa, base=0, offset = 0):
        """load a single executable extent from a file"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        # first, assemble

        fp.seek(offset, os.SEEK_CUR)
        assembled = bytes(keystone.Ks(_isa["keystone"]["arch"],
            _isa["keystone"]["endianness"] + _isa["keystone"]["mode"]).asm(
                fp.read())[0])

        # disassemble

        return MachineCodeIO.load(io.BytesIO(assembled), _isa, base)

    @staticmethod
    def pdump(path, extent):
        """dump a single executable extent to a path"""
        with open(path, "wb") as fp:
            AssemblyIO.dump(fp, extent)

    @staticmethod
    def pload(path, _isa, base=0, offset = 0):
        """load a single executable extent at a path"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path, "rb") as fp:
            return AssemblyIO.load(fp, _isa, base, offset)


class MachineCodeIO(AssemblyIO):
    """machine code de/serialization"""

    @staticmethod
    def dump(fp, extent):
        """load a single executable extent to a file"""
        _isa = isa.correlate(copy.deepcopy(extent["isa"]))

        # dump assembly

        b = io.BytesIO()
        AssemblyIO.dump(b, extent)

        # assemble

        fp.write(bytes(keystone.Ks(_isa["keystone"]["arch"],
                           _isa["keystone"]["endianness"] + _isa["keystone"]["mode"]).asm(
            b.getvalue())[0]))

    @staticmethod
    def load(fp, _isa, base=0, offset = 0):
        """load a single executable extent from a file"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        # load

        fp.seek(offset, os.SEEK_CUR)
        return {
            "base": base,
            "instructions": capstone.Cs(_isa["capstone"]["arch"],
                _isa["capstone"]["endianness"]
                    + _isa["capstone"]["mode"]).disasm(fp.read(),
                        base + offset),
            "isa": _isa,
            "offset": offset
        }

    @staticmethod
    def loadall(fp, base = 0, extents=None):
        """load all executable extents from a file"""

        # load the binary

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
            _base = extents[extent.name] \
                if isinstance(extents.get(extent.name, None), int) \
                else extent.addr
            code = io.BytesIO(extent.code)

            for offset in range(min(16, extent.size)): # Intel-specific##############################################################
                print("Loading extent from object (extent \"%s\", offset %u)..." % (extent.name, offset))
                code.seek(0, os.SEEK_SET)
                extents[(extent.name, offset)] = MachineCodeIO.load(
                    io.BytesIO(code.read()), _isa, base + _base, offset)

        # filter out unmatched extents

        return {k: v for k, v in extents.items() if len(v.keys()) > 1}

    @staticmethod
    def pdump(path, extent):
        """load a single executable extent to a path"""
        _isa = isa.correlate(copy.deepcopy(extent["isa"]))

        with open(path, "wb") as fp:
            MachineCodeIO.dump(fp, extent)

    @staticmethod
    def pload(path, _isa, base=0, offset = 0):
        """load a single executable extent at a path"""
        _isa = isa.correlate(copy.deepcopy(_isa))

        with open(path, "rb") as fp:
            return MachineCodeIO.load(fp, base, offset)

    @staticmethod
    def ploadall(path, base = 0, extents=None):
        """load all executable extents at a path"""
        with open(path, "rb") as fp:
            return MachineCodeIO.loadall(fp, base, extents)


if __name__ == "__main__":
    # test loading from a binary

    compiled = MachineCodeIO.ploadall("../libc.so.6")

    for name_offset, extent in compiled.items():
        print("\"%s\", offset %u" % name_offset)

        for i in extent["instructions"]:
            print("\t0x%.16x\t%s\t%s" % (i.address, i.mnemonic, i.op_str))
    sys.exit()
    print(compiled)
    source = AssemblyIO.pload("../x86-32-little.S", isa.parse("x86-32-little"))
    print(source)

    # test dumping to assembly/machine code (not a full binary)

    with os.fdopen(sys.stdout.fileno(), "wb") as fp:
        AssemblyIO.dump(fp, source)
        MachineCodeIO.dump(fp, source)

