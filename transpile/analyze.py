import capstone
import filebytes.elf
import filebytes.mach_o
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


class CodeSlice:
    def __init__(self, header_type, name, binary, addr, offset):
        self.header_type = header_type
        self.name = name
        self.binary = binary
        self.addr = addr
        self.offset = offset

    @property
    def size(self):
        return len(self.binary)


class Binary:
    def __init__(self, binary):
        self.binary = binary
        self.type = None
        self.arch = None
        self.mode = None
        self.endianess = None
        self.e_point = None
        self.isa = None

        self.parse()

    def parse(self):
        if not self.type:
            self.identify()
        # parse
        if self.type == "ELF":
            self.parse_elf()
        elif self.type == "MACHO":
            self.parse_macho()

    def parse_elf(self):
        self.elf_file = filebytes.elf.ELF(None, fileContent=self.binary)
        """architecture"""
        self.arch = ELF_ARCH[filebytes.elf.EM[self.elf_file.elfHeader.header.e_machine]]
        """mode"""
        self.mode = ELF_MODE[self.elf_file.elfHeader.header.e_ident[filebytes.elf.EI.CLASS]]
        """endianess"""
        self.endianess = ELF_ENDIAN[self.elf_file.elfHeader.header.e_ident[filebytes.elf.EI.DATA]]
        """entry point"""
        self.e_point = self.elf_file.entryPoint
        """segments"""
        self.segments = self.elf_file.segments
        """sections"""
        self.sections = self.elf_file.sections
        # print(hex(self.e_point))

    def parse_macho(self):
        raise NotImplementedError

    def identify(self):
        """Auto-identify the type of binary"""
        if self.elf_check(self.binary):
            self.type = "ELF"
        elif self.macho_check(self.binary):
            self.type = "MACHO"
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

    @property
    def executable_sections(self):
        """get the executable sections"""
        if not self.executable_sections:
            self.executable_sections = list()
            for phdr in self.segments:
                if phdr.header.p_flag & filebytes.elf.PF.EXEC > 0:
                    self.executable_sections += [CodeSlice("program",
                                                           str(
                                                               filebytes.elf.PT[phdr.header.p_type]),
                                                           phdr.raw,
                                                           phdr.header.p_vaddr,
                                                           phdr.header.p_offset)]
            for shdr in self.sections:
                if shdr.header.sh_flag & filebytes.elf.SHF.EXECINSTR:
                    self.executable_sections += [CodeSlice("section",
                                                           shdr.name,
                                                           shdr.raw,
                                                           shdr.header.sh_addr,
                                                           shdr.header.offset)]
        return self.executable_sections


ELF_ARCH = {
    filebytes.elf.EM[filebytes.elf.EM.INTEL_386]: capstone.CS_ARCH_X86,
    filebytes.elf.EM[filebytes.elf.EM.INTEL_80860]: capstone.CS_ARCH_X86,
    filebytes.elf.EM[filebytes.elf.EM.X86_64]: capstone.CS_ARCH_X86
}

ELF_MODE = {
    filebytes.elf.ELFCLASS.BITS_32: capstone.CS_MODE_32,
    filebytes.elf.ELFCLASS.BITS_64: capstone.CS_MODE_64
}

ELF_ENDIAN = {
    filebytes.elf.ELFDATA.LSB: capstone.CS_MODE_LITTLE_ENDIAN,
    filebytes.elf.ELFDATA.MSB: capstone.CS_MODE_BIG_ENDIAN,
}
