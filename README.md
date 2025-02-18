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
- ~~`iio`~~
	- ~~`AssemblyIO`~~
	- ~~`BaseInstructionIO`~~
	- ~~`MachineCodeIO`~~
		- ~~`loadall`~~
	- ~~**test**~~
- `__init__`
	- `__doc__`
	- ~~imports~~
- ~~`isa`~~
	- ~~`binary`~~
	- ~~`correlate`~~
	- ~~`parse`~~
	- ~~**test**~~
- `__main__`
	- `main`
		- ~~adapt to `mprotect` interface~~
			- ~~add `buf`/`buflen` options to the CLI~~
			- ~~`chain` option~~
				- ~~`mprotect` sub-option~~
		- ~~argument validation~~
		- ~~adapt to `iio.*.pload*`~~
		- ~~properly handle no arguments (print help message & return 1)~~
- `transpile`
	- `Transpiler`
		- rethink `__init__` interface (move args to `__call__`?)
		- `__call__`
			- ~~obtain gadgets~~
			- construct frames
			- function arguments (maybe the input/output format
				should be specialized?)
		- ~~`chain`~~
		- ~~`_inc_reg_n`~~
		- `_reg_assign`
			- `pop TEMP; mov REG` -> second-most preferable
		- `mprotect`
			- per-ISA discrimination (favor x86-32/Linux)
			- MUST treat subchains as containing mixed values
				(e.g. bytes and integers (integers should be
				interpreted as register contents))
	- **test**
- agnosticize implementation (from x86-32-Little to any x86/MIPS combo)
- ARGUMENT VALIDATION
- demo

# Sources
- [Capstone](https://www.capstone-engine.org)
- [ELF](https://wiki.osdev.org/ELF)
- [Filebytes]()
- [Keystone](https://www.keystone-engine.org)
- [Netwide Assembler]()

