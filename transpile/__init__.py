try:
    from . import analyze, gadget, iio, isa, transpile
except ImportError:
    import os
    import sys

    sys.path.append(os.path.realpath(__file__))

    import analyze
    import gadget
    import iio
    import isa
    import transpile

__doc__ = "transpiler library"

