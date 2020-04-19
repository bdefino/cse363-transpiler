# included flags from https://github.com/JonathanSalwan/ROPgadget/blob/master/ropgadget/loaders/elf.py

class ELFFlags(object):
    ELFCLASS32    = 0x01
    ELFCLASS64    = 0x02
    EI_CLASS      = 0x04
    EI_DATA       = 0x05
    ELFDATA2LSB   = 0x01
    ELFDATA2MSB   = 0x02
    EM_386        = 0x03
    EM_X86_64     = 0x3e
    EM_ARM        = 0x28
    EM_MIPS       = 0x08
    EM_SPARCv8p   = 0x12
    EM_PowerPC    = 0x14
    EM_ARM64      = 0xb7

class MACHOFlags(object):
    CPU_TYPE_I386               = 0x7
    CPU_TYPE_X86_64             = (CPU_TYPE_I386 | 0x1000000)
    CPU_TYPE_MIPS               = 0x8
    CPU_TYPE_ARM                = 12
    CPU_TYPE_ARM64              = (CPU_TYPE_ARM | 0x1000000)
    CPU_TYPE_SPARC              = 14
    CPU_TYPE_POWERPC            = 18
    CPU_TYPE_POWERPC64          = (CPU_TYPE_POWERPC | 0x1000000)
    LC_SEGMENT                  = 0x1
    LC_SEGMENT_64               = 0x19
    S_ATTR_SOME_INSTRUCTIONS    = 0x00000400
    S_ATTR_PURE_INSTRUCTIONS    = 0x80000000


class Header():
  def __init__(self, binary):
    self.__binary = bytearray(binary)
    self.__type = None
    self.__











