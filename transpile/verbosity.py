#!/bin/env python3
import os

__doc__ = "centralized verbosity"

class Verbose():
    def __init__(self, level):
        self.level = level
        if self.level:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            self.file = sys.stderr

    def enter(self, name, *args):
        if self.level:
            print("Entering "+name+"(", end="", file=self.file)
            for i in range(len(args)):
                e = "" if i == len(args) - 1 else ", "
                print(str(args[i]), end=e, file=self.file)
            else:
                print(")", file=self.file)

    def log(self, msg):
        if self.level:
            print(msg, file=self.file)

    def leave(self, name, retval):
        if self.level:
            print("Exiting " + name + "() with return value'" +
                  str(retval)+"''", file=self.file)

    def close(self):
        if self.level:
            self.file.close()
