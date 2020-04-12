#!/usr/bin/env python3
import getopt
import sys

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


import .transpile
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
    -o FILE
        output the ROP payload to a file
        (defaults to STDOUT)
    -i
        instruction set of the TARGET(x86, MIPS, etc...)
    -r
        recurse into dynamic links

        this might break compatibility across drop-in replacements
        (e.g. LibreSSL and OpenSSL both appearing as `libssl`)
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
    recurse = False
    sources = {} # `{path: {segment: base address}}`
    target = None

    # parse arguments

    opts, args = getopt.getopt("hr+", argv[1:])

    try:
        target, sources = args[0], {k, v in (parse_source(a) for a in args[1:])}

        if not sources:
            raise ValueError()
    except ValueError:
        help(argv[0])
        return 1
    
    for k, v in opts:
        if k == "-h":
            help(argv[0])
            return 0
        elif k == "-r":
            recurse = True
    transpile.Transpiler(target)(*objs)
    return 0

def parse_source(a):
    raise NotImplementedError()##################################################

if __name__ == "__main__":
    sys.exit(main(sys.argv))

