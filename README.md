# cse363-transpiler
*SBU CSE 363 return-oriented programming project*

## Design
See [the SDD](SDD.md).

# To Do
- ~~`analyze`~~
	- ~~`Binary`~~
	- ~~`CodeSlice`~~
- ~~`gadget`~~
	- ~~`Gadgets`~~
		- ~~`search`~~
			- ~~regular expressions~~
			- ~~return `None` if unfound~~
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
	- ~~`binary`~~
	- ~~`correlate`~~
	- ~~`parse`~~
	- **test**
- `__main__`
	- `main`
		- ~~adapt to `mprotect` interface~~
			- ~~add `buf`/`buflen` options to the CLI~~
			- ~~`chain` option~~
				- ~~`mprotect` sub-option~~
- `transpile`
	- `Transpiler`
		- rethink `__init__` interface (move args to `__call__`?)
		- `__call__`
			- ~~obtain gadgets~~
			- construct frames
			- function arguments (maybe the input/output format
				should be specialized?)
		- `chain`
		- `_inc_reg_n`
		- `_regassign`
		- `mprotect`
			- MUST treat subchains as containing mixed values
				(e.g. bytes and integers (integers should be
				interpreted as register contents))
	- **test**

# Sources
- [Capstone](https://www.capstone-engine.org)
- [ELF](https://wiki.osdev.org/ELF)
- [Filebytes]()
- [Keystone](https://keystone-engine.org)
- [Netwide Assembler]()

