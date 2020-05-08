# cse363-transpiler
*SBU CSE 363 return-oriented programming project*

## Design
See [the SDD](SDD.md).

# To Do
- `analyze`
	- ~~`Binary`~~
	- ~~`CodeSlice`~~
- `gadget`
	- `Gadgets`
- `iio`
	- `AssemblyIO`
	- `pload`
	- `BaseInstructionIO`
	- `MachineCodeIO`
	- **test**
- `__init__`
	- `__doc__`
	- ~~imports~~
- `isa`
	- `parse`
- `__main__`
	- `main`
- `transpile`
	- `Transpiler`
		- `__call__`
			- obtain gadgets
			- construct frames
			- function arguments (maybe the input/output format
				should be specialized?)
	- **test**

# Sources
- [ELF](https://wiki.osdev.org/ELF)
- [Netwide Assembler]()

