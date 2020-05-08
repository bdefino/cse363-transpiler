import capstone
import keystone

try:
    from . import analyze
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import analyze

__doc__ = "instruction set/architecture representation"

def binary(binary):
    """extract an appropriate mode from a `Binary`"""
    if not isinstance(binary, analyze.Binary):
        raise TypeError("expected an `analyze.Binary`")
    return correlate({"capstone": (binary.arch, binary.mode)})

def correlate(isa):
    """correlate a capstone/keystone ISA"""
    if not "capstone" in isa \
            and not "keystone" in isa:
        raise KeyError("expected either a capstone or keystone ISA")
    elif "capstone" in isa \
            and "keystone" in isa:
        return isa
    elif "capstone" in isa:
        isa["keystone"] = [None, None]

        if isa["capstone"][0] == capstone.CS_ARCH_MIPS:
            isa["keystone"] = keystone.KS_ARCH_MIPS
        elif isa["capstone"][0] == capstone.CS_ARCH_X86:
            isa["keystone"] = keystone.KS_ARCH_MIPS
        else:
            raise ValueError("unsupported architecture")

        if isa["capstone"][1] == capstone.CS_MODE_32:
            isa["keystone"][1] = keystone.KS_MODE_32
        elif isa["capstone"][1] == capstone.CS_MODE_64:
            isa["keystone"][1] = keystone.KS_MODE_64
        else:
            raise ValueError("unsupported mode")
    else:
        isa["capstone"] = [None, None]

        if isa["keystone"][0] == keystone.KS_ARCH_MIPS:
            isa["capstone"] = capstone.CS_ARCH_MIPS
        elif isa["keystone"][0] == keystone.KS_ARCH_X86:
            isa["capstone"] = capstone.CS_ARCH_MIPS
        else:
            raise ValueError("unsupported architecture")

        if isa["keystone"][1] == keystone.KS_MODE_32:
            isa["capstone"][1] = capstone.CS_MODE_32
        elif isa["keystone"][1] == keystone.KS_MODE_64:
            isa["capstone"][1] = capstone.CS_MODE_64
        else:
            raise ValueError("unsupported mode")

def parse(s):
    """parse an ISA string into a capstone `(arch, mode)`"""
    arch = None
    components = [""]
    mode = None
    output = {k: [None, None] for k in ("capstone", "keystone")}
    s = s.lower()

    for c in s:
      if c.isspecial():
          components.append("")
          continue
      components[-1] += c

    try:
        arch, mode = filter(components)
    except ValueError:
        raise ValueError("invalid ISA")

    # classify architecture

    if arch == "mips":
        output["capstone"][0] = capstone.CS_ARCH_MIPS
        output["keystone"][0] = keystone.KS_ARCH_MIPS
    elif arch == "x86":
        output["capstone"][0] = capstone.CS_ARCH_X86
        output["keystone"][0] = keystone.KS_ARCH_X86

    # classify mode

    if mode == "32":
        output["capstone"][1] = capstone.CS_MODE_32
        output["keystone"][1] = keystone.KS_MODE_32
    elif mode == "64":
        output["capstone"][1] = capstone.CS_MODE_64
        output["keystone"][1] = keystone.KS_MODE_64
    return {k: tuple(v) for k, v in output.items()}

