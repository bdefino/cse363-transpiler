import capstone
import re

try:
    from . import iio
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import iio


class Gadgets:
    def __init__(self, cap):
        self.cap = cap
        self.gadgets = {}
        self.depth = 5
        self.find_gadgets()

    def __doc__(self):
        return "find gadgets from disassembled binary"

    def __repr__(self):
        return self.gadgets

    def __str__(self):
        s = ''
        for v in self.gadgets.values():
            s += self.__tostring(v) + '\n'
        return s

    def __tostring(self, values):
        s = "0x{}\t".format(str(values[0][0]))
        for v in values:
            s += "{}; ".format(v[1])
        return s.rstrip(' ')

    def find_gadgets(self):
        """output: 
        gadgets{
            return address: [gadget address, [gadgets]]
            ...
        }
        """
        instrc = reversed(list(self.cap))
        isgadget = False  # gadget chain
        g_point = None  # gadget pointer / ret addr

        for i in instrc:
            if i.mnemonic == "ret":
                isgadget = True  # start gadget chain
                g_point = i.address
                self.gadgets[g_point] = []

            if isgadget:
                self.gadgets[g_point].insert(
                    0, (i.address, i.mnemonic + (' ' if i.op_str else '') + i.op_str))
                if len(self.gadgets[g_point]) > self.depth:
                    isgadget = False  # end gadget chain

    def search(self, pattern, verbose=0):
        """ verbose level:
            0 = no output
            1 = print gadget found
            2 = print gadget found + gadget string
            3 = print gadget not found
        """
        pattern = "; ".join(i.strip() for i in pattern.split(';') if i.strip())

        glist = {}
        if verbose:
            print("pattern:", pattern)

        for v in self.gadgets.values():
            addr = v[0][0]
            g = self.__tostring(v)
            if re.search(pattern, g):
                if verbose >= 2:
                    print(g)
                glist[addr] = v

        if glist != {}:
            if verbose >= 1:
                print("gadget found")
            return self.parse_glist(glist, pattern)
        else:
            if verbose >= 3:
                print("gadget not found")
            return {}

    def parse_glist(self, gin, p):
        gout = {}
        plen = len(p.split(';'))

        for _, v in gin.items():
            for i in range(len(v)-plen+1):
                s = self.__tostring(v[i:i+plen]).split('\t')[1]
                if re.match(p, s):
                    gout[v[i][0]] = s
        return gout


if __name__ == "__main__":
    compiled = iio.MachineCodeIO.ploadall("../libc.so.6")
    print(compiled.keys())
    g = Gadgets(compiled["instructions"])

    print(g)
    print('----------------')
    print("search return:", g.search('pop ...; ret ;', 2))
