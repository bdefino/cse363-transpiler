#!/usr/bin/env python3
import getopt
import sys
import traceback

from . import iio, isa, transpile, verbosity

'''
Question:
attacker machine:
Source[:BASE+offset]
payload:
gadget offset 1 0x1   (abs addr on victim's machine)
gadget offset 2 0x100
...
gadget offset n 0xFFFF

attacker's machine:
cat payload | telnet SERVER
'''

###########################################################################ASLR?
__doc__ = """transpile: compose an ROP payload
Usage: transpile [OPTIONS] TARGET SOURCE[:SECTION=BASE...] ...
BASE
  force overwrite the base address for a SECTION within a SOURCE
OPTIONS
    -a
        explore all possible gadgets
        (via DAG comparisons)
    -h
        print this text and exit
    -i
        instruction set of the TARGET(x86, MIPS, etc...)
    -o FILE
        output the ROP payload to a file
        (defaults to STDOUT)
    -r
        recurse into dynamic links

        this might break compatibility across drop-in replacements
        (e.g. LibreSSL and OpenSSL both appearing as `libssl`)
    -t
        treat TARGET as a text file
        (assembly; defaults to treating it as machine code)
    -v
        enable verbosity
SECTION
    a section name within a SOURCE
SOURCE
    source file (`.dll`, ELF, `.o`, PE, `.so`, etc.)
TARGET
    the desired behavior (an assembly file of shell code)"""

def help(name):
    print(__doc__ % name, file = sys.stderr)

def main(argv):
    all_permutations = False
    isas = None # required
    opath = '-'
    recurse = False
    sources = {} # `{path: {segment: base address}}`
    target = None
    text = False
    verbosity = 0

    # parse arguments

    opts, args = getopt.getopt("aho:rtv+", argv[1:])

    try:
        target, sources = args[0], {k, v in (parse_source(a) for a in args[1:])}

        if not sources:
            raise ValueError()
    except ValueError:
        help(argv[0])
        return 1

    for k, v in opts:
        if k == "-a":
            all_permutations = True
        elif k == "-h":
            help(argv[0])
            return 0
        elif k == "-i":
            isas = v
        elif k == "-o":
            opath = v
        elif k == "-r":
            recurse = True
        elif k == "-t":
            text = True
        elif k == "-v":
            verbosity += 1

    if not isa:
        print("Empty ISA.", file = sys.stderr)
        help(argv[0])
        return 1

    try:
        target = (iio.AssemblyIO if text else iio.MachineCodeIO).load(isa.parse(isas), target)
        verbosity = verbosity.Verbosity()######################################################################
        output = transpile.Transpiler(target, all_permutations, recurse, verbosity)(*objs)

        if opath == '-':
            iio.AssemblyIO.dump(output, sys.stdout)
        else:
            with open(opath, "wb") as fp:
                output.dump(fp)
    except Exception as e:
        traceback.format_exc(*e)
        return 1
    return 0

def parse_source(s):
    """parse `(path, {section: base})` from `"PATH[:SECTION=BASE...]"`"""
    path = None
    sections = {}

    if ':' in s:
        path, s = s.split(':', 1)

        for sb in s.split(':'):
            if not '=' in sb:
                raise ValueError("invalid section specifier")

            try:
                section, base = sb.split('=')
                sections[section] = int(base)
            except ValueError:
                raise ValueError("invalid section specifier")
    return path, sections

if __name__ == "__main__":
    sys.exit(main(sys.argv))
