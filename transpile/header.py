import capstone
import filebytes
import struct


class ELFMagic(object):
    MAGIC = [0x7F454C46]
    OFFSET = [0x0]
    SIZE = 4


class MACHOMagic(object):
    MAGIC = [0xFEEDFACE, 0xFEEDFACF]
    OFFSET = [0x0, 0x1000]
    SIZE = 4


class PEMagic(object):
    MAGIC = [0x4D5A]
    OFFSET = [0x0]
    SIZE = 2


class Header:
    def __init__(self, binary):
        self.binary = binary
        self.format = None
        self.endianess = None
        self.isa = None
        self.mode = None
        self.entry_point = None

    def identify(self):
        """Auto-identify the type of binary"""
        if self.elf_check(self.binary):
            print("ELF")
        if self.macho_check(self.binary):
            print("MachO")
        """PE check"""

    def elf_check(self, binary):
        """ELF check"""
        """Big Endian"""
        if struct.pack(">I", ELFMagic.MAGIC[0]) == binary[ELFMagic.OFFSET[0]: ELFMagic.SIZE]:
            return True
        """Little Endian"""
        if struct.pack("<I", ELFMagic.MAGIC[0]) == binary[ELFMagic.OFFSET[0]: ELFMagic.SIZE]:
            return True
        return False

    def macho_check(self, binary):
        """MachO check"""
        """Big Endian"""
        if struct.pack(">I", MACHOMagic.MAGIC[0]) == binary[MACHOMagic.OFFSET[0]: MACHOMagic.SIZE]:
            return True
        if struct.pack(">I", MACHOMagic.MAGIC[0]) == binary[MACHOMagic.OFFSET[1]: MACHOMagic.SIZE]:
            return True
        if struct.pack(">I", MACHOMagic.MAGIC[1]) == binary[MACHOMagic.OFFSET[0]: MACHOMagic.SIZE]:
            return True
        if struct.pack(">I", MACHOMagic.MAGIC[1]) == binary[MACHOMagic.OFFSET[1]: MACHOMagic.SIZE]:
            return True
        """Little Endian"""
        if struct.pack("<I", MACHOMagic.MAGIC[0]) == binary[MACHOMagic.OFFSET[0]: MACHOMagic.SIZE]:
            return True
        if struct.pack("<I", MACHOMagic.MAGIC[0]) == binary[MACHOMagic.OFFSET[1]: MACHOMagic.SIZE]:
            return True
        if struct.pack("<I", MACHOMagic.MAGIC[1]) == binary[MACHOMagic.OFFSET[0]: MACHOMagic.SIZE]:
            return True
        if struct.pack("<I", MACHOMagic.MAGIC[1]) == binary[MACHOMagic.OFFSET[1]: MACHOMagic.SIZE]:
            return True
        return False
