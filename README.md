# cse363-transpiler
*SBU CSE 363 return-oriented programming project*

## Design
See [the SDD](SDD.md).

# To Do
- `analyze`
	- ~~`Binary`~~
	- ~~`CodeSlice`~~
- `gadget` (Junming)
	- `Gadgets`
		- `search`
			- regular expressions
- `iio` (Bailey)
	- `AssemblyIO`
	- `pload`
	- `BaseInstructionIO`
	- `MachineCodeIO`
	- **test**
- `__init__`
	- `__doc__`
	- ~~imports~~
- `isa` (Bailey)
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
			- primary option for register loading: `pop REG`
				- secondary option: addition
	- **test**

# Sources
- [Capstone](https://www.capstone-engine.org)
- [ELF](https://wiki.osdev.org/ELF)
- [Filebytes]()
- [Keystone](https://keystone-engine.org)
- [Netwide Assembler]()

