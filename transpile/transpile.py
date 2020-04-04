import capstone

class Transpiler:
    def __init__(self, target):
        self.target = target
    
    def __call__(self, *objs):
        raise NotImplementedError()##################################################

