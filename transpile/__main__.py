#!/usr/bin/env python3
import getopt
import sys
import traceback

try:
    from . import iio, isa, transpile
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import iio
    import isa
    import transpile


__doc__ = """transpile: compose an ROP payload
Usage: %s [OPTIONS] TARGET SOURCE[=BASE][:SECTION=BASE...] ...
BASE
    force overwrite the base address for a specific SECTION,
    or the entire SOURCE
EXAMPLES
    make the stack executable for the 2-byte payload at address 1:
        `%s -b 1 -c -l 2 -p 3 mprotect /usr/lib32/libc.so`
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
    -i ISAS
        instruction set of the TARGET(x86-64, MIPS-32, etc...)
    -l LENGTH
        buffer length (contextual)
    -o FILE
        output the ROP payload to a file
        (defaults to STDOUT)
    -p ADDR
        where the ROP payload will be located on the victim's machine
    -r
        recurse into dynamic links

        this might break compatibility across drop-in replacements
        (e.g. LibreSSL and OpenSSL both appearing as `libssl`)
    -t
        treat TARGET as a text file
        (assembly; defaults to treating it as machine code)
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
    print(__doc__ % (name, name), file = sys.stderr)

def main(argv):
    all_permutations = False
    buf = None
    buflen = None
    chain = False
    isas = None # required
    opath = '-'
    recurse = False
    rop = None
    sources = {} # `{path: {segment: base address}}`
    target = None
    text = False

    # parse arguments

    opts, args = getopt.getopt(argv[1:], "ab:chi:l:o:p:rt+")

    if not args:
        help(argv[0])
        return 1

    try:
        target, sources = args[0], {k: (b, v) for k, b, v in (parse_source(a)
            for a in args[1:])}

        if not sources:
            raise ValueError()
    except ValueError:
        print("Empty sources")
        help(argv[0])
        return 1

    for k, v in opts:
        if k == "-a":
            all_permutations = True
        elif k == "-b":
            try:
                buf = parse_int(v)
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
                buflen = parse_int(v)
            except ValueError:
                print("Invalid length.", file = sys.stderr)
                help(argv[0])
                return 1
        elif k == "-o":
            opath = v
        elif k == "-p":
            try:
                rop = parse_int(v)
            except ValueError:
                print("Invalid address.", file = sys.stderr)
                help(argv[0])
                return 1
        elif k == "-r":
            recurse = True
        elif k == "-t":
            text = True

    if not isas \
            and not chain:
        print("Empty ISA.", file = sys.stderr)
        help(argv[0])
        return 1

    try:
        sources = [iio.MachineCodeIO.ploadall(k, v[0], **v[1])
            for k, v in sources.items()]

        if chain:
            output = transpile.Transpiler.chain(target, buf = buf,
                buflen = buflen, rop = rop, *sources)
        else:
            if text:
                target = {None: iio.AssemblyIO.pload(target, isa.parse(isas))}
            else:
                target = iio.MachineIO.ploadall(target)
            #target = (iio.AssemblyIO if text else iio.MachineCodeIO).load(isa.parse(isas), target)
            output = transpiler.Transpiler(target, all_permutations, recurse)

        if opath == '-':
            with os.fdopen(sys.stdout.fileno(), "wb") as fp:
                fp.write(output)
        else:
            with open(opath, "wb") as fp:
                fp.write(output)
    except Exception as e:
        traceback.print_exception(type(e), e, e.__traceback__, file=sys.stderr)
        return 1
    return 0

def parse_int(s):
    """parse an integer in (hexa)decimal"""
    if set(s).intersection(set("abcdef")) \
            or s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)

def parse_source(s):
    """parse `(path, base, {section: base})` from `"PATH[:SECTION=BASE...]"`"""
    base = 0
    path = s
    sections = {}

    if ':' in s:
        if '=' in s:
            path, s = s.split('=', 1)
            base, s = s.split(':', 1)
            base = parse_int(base)
        else:
            path, s = s.split(':', 1)

        for sb in s.split(':'):
            if not '=' in sb:
                raise ValueError("invalid section specifier")

            try:
                section, base = sb.split('=')
                sections[section] = parse_int(base)
            except ValueError:
                raise ValueError("invalid section specifier")
    elif '=' in s:
        path, s = s.split('=', 1)
        base = parse_int(s)
    return path, base, sections

if __name__ == "__main__":
    sys.exit(main(sys.argv))

