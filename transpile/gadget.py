#!/bin/env python3
import capstone


class Gadgets:
    def __init__(self, cap):
        self.cap = cap
        self.gadgets = {}
        self.depth = 5
    
    def __doc__(self):
        return "find gadgets from disassembled binary"

    def __repr__(self):
        return self.gadgets

    def __str__(self):
        s = ''
        for k in self.gadgets.keys():
            s += self.tostring(k) + '\n'
        return s

    def tostring(self, ret):
        v = self.gadgets[ret]
        s = "0x" + str(v[0]) + '\t'
        s += " ; ".join(v[1:])
        return s

    def find_gadgets(self):
        """output: 
        gadgets{
            return address: [gadget address, [gadgets]]
            ...
        }
        """
        instrc = reversed(list(self.cap))
        isgadget = False    #gadget chain
        g_point = None      #gadget pointer / ret addr

        for i in instrc:
            if i.mnemonic == "ret":
                isgadget = True    #start gadget chain
                g_point = i.address
                self.gadgets[g_point] = ["addr"]
            
            if isgadget:
                self.gadgets[g_point][0] = i.address
                self.gadgets[g_point].insert(1, i.mnemonic + " " + i.op_str)
                if len(self.gadgets[g_point]) > self.depth:
                    isgadget = False    #end gadget chain

    def list_all(self):
        for i, j in self.gadgets.items():
            print("ret addr: 0x%x\t" %i, "gadgets:", j)

    def search(self, pattern):
        print("target:", pattern)
        for k in self.gadgets.keys():
            gadget = self.tostring(k)
            if pattern in gadget:
                print(gadget)



code = b"\x4d\x39\x52\x54\x67\xc3\x5e\x72\x93\xe3\x73\x72\x5a\x5c\xc3\xc3"


md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)


g = Gadgets(md.disasm(code, 0x0))
g.find_gadgets()
g.list_all()
print('----------------')
g.search('pop esp')
print('----------------')
print(g)
