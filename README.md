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
		- `search`
			- regular expressions
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
		- adapt to `mprotect` interface
- `transpile`
	- `Transpiler`
		- `__call__`
			- obtain gadgets
			- construct frames
			- function arguments (maybe the input/output format
				should be specialized?)
		- ~~`chain`~~
		- `mprotect`
	- **test**

# Sources
- [Capstone](https://www.capstone-engine.org)
- [ELF](https://wiki.osdev.org/ELF)
- [Filebytes]()
- [Keystone](https://keystone-engine.org)
- [Netwide Assembler]()

