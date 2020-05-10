#!/usr/bin/env python3
import getopt
import sys
import traceback

try:
    from . import iio, isa, transpile, verbosity
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import iio
    import isa
    import transpile
    import verbosity

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
    -b ADDR
        buffer address (contextual)
    -c
        TARGET is a chain
        (takes precedence over `-t`)
    -h
        print this text and exit
    -i
        instruction set of the TARGET(x86-64, MIPS-32, etc...)
    -l LENGTH
        buffer length (contextual)
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
    the desired behavior (an assembly file of shell code)

    if `-c` is also provided, this is one of the following chain names:
        `mprotect`
            expects `-b` and `-l` to represent the secondary payload
        (more to come)"""

def help(name):
    print(__doc__ % name, file = sys.stderr)

def main(argv):
    from . import test
    return test.test()##########################################################################
    all_permutations = False
    buf = None
    buflen = None
    chain = False
    isas = None # required
    opath = '-'
    recurse = False
    sources = {} # `{path: {segment: base address}}`
    target = None
    text = False
    verbosity = 0

    # parse arguments

    opts, args = getopt.getopt("ab:chl:o:rtv+", argv[1:])

    try:
        target, sources = args[0], {k, v in (parse_source(a)
            for a in args[1:])}

        if not sources:
            raise ValueError()
    except ValueError:
        help(argv[0])
        return 1

    for k, v in opts:
        if k == "-a":
            all_permutations = True
        elif k == "-b":
            try:
                buf = int(v)
            except ValueError:
                print("Invalid address.", file = sys.stderr)
                help(argv[0])
                return 1
        elif k == "-c":
            chain = True
        elif k == "-h":
            help(argv[0])
            return 0
        elif k == "-i":
            isas = v
        elif k == "-l":
            try:
                buflen = int(v)
            except ValueError:
                print("Invalid length.", file = sys.stderr)
                help(argv[0])
                return 1
        elif k == "-o":
            opath = v
        elif k == "-r":
            recurse = True
        elif k == "-t":
            text = True
        elif k == "-v":
            verbosity += 1

    if not isas:
        print("Empty ISA.", file = sys.stderr)
        help(argv[0])
        return 1

    try:
        if not chain:
            target = (iio.AssemblyIO if text else iio.MachineCodeIO).load(
                isa.parse(isas), target)
        verbosity = verbosity.Verbosity()######################################################################
        transpiler = transpile.Transpiler(target, all_permutations, recurse,
            verbosity)

        if chain:
            output = transpile.Transpiler.chain(target, buf = buf,
                buflen = buflen, *objs)
        else:
            target = (iio.AssemblyIO if text else iio.MachineCodeIO).load(
                isa.parse(isas), target)
            output = transpiler.

        if opath == '-':
            with open(sys.stdout, 
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

