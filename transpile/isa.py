import capstone
import keystone

__doc__ = "instruction set/architecture representation"

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

