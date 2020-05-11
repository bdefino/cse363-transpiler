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
    """extract an appropriate ISA from a `Binary`"""
    if not isinstance(binary, analyze.Binary):
        raise TypeError("expected an `analyze.Binary`")
    return correlate({
        "capstone": {
            "arch": binary.arch,
            "endianness": binary.endianness,
            "mode": binary.mode
        }
    })

def correlate(isa):
    """correlate a capstone/keystone ISA"""
    if not "capstone" in isa \
            and not "keystone" in isa:
        raise KeyError("expected either a Capstone or Keystone ISA")
    elif "capstone" in isa \
            and "keystone" in isa:
        return isa
    elif "capstone" in isa:
        isa["keystone"] = {}

        if isa["capstone"]["arch"] == capstone.CS_ARCH_MIPS:
            isa["keystone"]["arch"] = keystone.KS_ARCH_MIPS
        elif isa["capstone"]["arch"] == capstone.CS_ARCH_X86:
            isa["keystone"]["arch"] = keystone.KS_ARCH_X86
        else:
            raise ValueError("unsupported architecture")

        if isa["capstone"]["endianness"] == capstone.CS_MODE_BIG_ENDIAN:
            isa["keystone"]["endianness"] = keystone.KS_MODE_BIG_ENDIAN
        elif isa["capstone"]["endianness"] == capstone.CS_MODE_LITTLE_ENDIAN:
            isa["keystone"]["endianness"] = keystone.KS_MODE_LITTLE_ENDIAN
        else:
            raise ValueError("unsupported endianness")

        if isa["capstone"]["mode"] == capstone.CS_MODE_32:
            isa["keystone"]["mode"] = keystone.KS_MODE_32
        elif isa["capstone"]["mode"] == capstone.CS_MODE_64:
            isa["keystone"]["mode"] = keystone.KS_MODE_64
        else:
            raise ValueError("unsupported mode")
    else:
        isa["capstone"] = {}

        if isa["keystone"]["arch"] == keystone.KS_ARCH_MIPS:
            isa["capstone"]["arch"] = capstone.CS_ARCH_MIPS
        elif isa["keystone"]["arch"] == keystone.KS_ARCH_X86:
            isa["capstone"]["arch"] = capstone.CS_ARCH_X86
        else:
            raise ValueError("unsupported architecture")

        if isa["keystone"]["endianness"] == keystone.KS_MODE_BIG_ENDIAN:
            isa["capstone"]["endianness"] = capstone.CS_MODE_BIG_ENDIAN
        elif isa["keystone"]["endianness"] == keystone.KS_MODE_LITTLE_ENDIAN:
            isa["capstone"]["endianness"] = capstone.CS_MODE_LITTLE_ENDIAN
        else:
            raise ValueError("unsupported endianness")

        if isa["keystone"]["mode"] == keystone.KS_MODE_32:
            isa["capstone"]["mode"] = capstone.CS_MODE_32
        elif isa["keystone"]["mode"] == keystone.KS_MODE_64:
            isa["capstone"]["mode"] = capstone.CS_MODE_64
        else:
            raise ValueError("unsupported mode")
    return isa

def parse(s):
    """
    parse an ISA string (e.g. "x86-64-Little") into:
    ```
    {
        "capstone": {
            "arch": arch,
            "endianness": "big" or "little" or None,
            "mode": mode
        },
        "keystone": {
            ... (same as previous)
        }
    }
    ```
    """
    arch = None
    components = [""]
    mode = None
    output = {
        "capstone": {},
        "keystone": {}
        }
    s = s.lower()

    for c in s:
        if not c.isalpha() and not c.isdigit():
            components.append("")
            continue
        components[-1] += c
    components = list(filter(None, components))

    if len(components) == 2:
        arch, mode = components
    elif len(components) == 3:
        arch, mode, output["capstone"]["endianness"] = components

        if output["capstone"]["endianness"] == "big":
            output["capstone"]["endianness"] = capstone.CS_MODE_BIG_ENDIAN
        elif output["capstone"]["endianness"] == "little":
            output["capstone"]["endianness"] = capstone.CS_MODE_LITTLE_ENDIAN
        else:
            raise ValueError("unsupported endianness")
    else:
        raise ValueError("invalid ISA")

    # classify architecture

    if arch == "mips":
        output["capstone"]["arch"] = capstone.CS_ARCH_MIPS
    elif arch == "x86":
        output["capstone"]["arch"] = capstone.CS_ARCH_X86
    else:
        print([components])
        raise ValueError("unsupported architecture")

    # classify mode

    if mode == "32":
        output["capstone"]["mode"] = capstone.CS_MODE_32
    elif mode == "64":
        output["capstone"]["mode"] = capstone.CS_MODE_64
    else:
        raise ValueError("unsupported mode")
    return correlate(output)

if __name__ == "__main__":
    # test

    isa = parse("x86-64-Little")
    print(isa)
    del isa["keystone"]
    print(correlate(isa))

