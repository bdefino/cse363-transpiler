# Transpiler Design and Specification
## Assignment
We were instructed to make an ROP payload generator for a single case.
But that's not interesting enough.

No, we decided to make a **full** transpiler.
Please read on.

## Description
The transpiler will analyze a file of desired shell code and translate this to a ROP paylaod. The program will do this by taking in a SOURCE binary and parse it for potential ROP gadgets. It will construct a payload of ROP gadgets to execute the desired shell code, based on the TARGET. 

# Prerequistes
Python3
Capstone
> `pip install capstone` or `easy_install capstone`

# Usage
Here's the command-line usage:
```
transpile: compose an ROP payload
Usage: transpile [OPTIONS] TARGET SOURCE[:SECTION=BASE...] ...
BASE
  force overwrite the base address for a SECTION within a SOURCE
OPTIONS
    -a
        explore all possible gadgets
        (via DAG comparisons)
    -h
        print this text and exit
    -o FILE
        output the ROP payload to a file
        (defaults to STDOUT)
    -i
        instruction set of the TARGET(x86, MIPS, etc...)
    -r
        recurse into dynamic links

        this might break compatibility across drop-in replacements
        (e.g. LibreSSL and OpenSSL both appearing as `libssl`)
    -v
        enable verbosity
SECTION
    a section name within a SOURCE
SOURCE
    source file (`.dll`, ELF, `.o`, PE, `.so`, etc.)
TARGET
    the desired behavior (an assembly file of shell code)
```

## Expect Input/Output
Here's an example w/ ASLR compensation:
```
./transpile.py -v MY_TARGET SRC:init=0xFF:text=0x32
...Analyzing Target File...
Instruction 1 ==> <Line 1 of asm>
Instruction 2 ==> <Line 2 of asm>
Instruction 3 ==> <Line 3 of asm>
...
Instruction n ==> <Line n of asm>
...Parsing Binary...
Locate gadgets for Instruction n
Gadget found!
Gadget found!
Gadget found!
Instruction n ==> (<the gadget that was found>,<starting addr of gadget>, ...)
Saving this gadget group for instruction n
...
...Tranpiling...
Arranging the gadget groups based on the target.
Output:
<ROP Payload>

./transpile.py MY_TARGET SRC
Output:
<ROP Payload> 
```

## Design
### Philosophy
Stuff's already overcomplicated, so we chose the simple route: that old Unix maxim.
'A program should do just one thing, and do it well.'

In short, we're covering our bases.

### Structure

## Implementation
The transpiler will read the binary and locate a gadget. Capstone will help us with this.

For ROP, the transpiler will look at the `ret` instructions and be able to construct gadgets. A permutations of gadgets are then able to translate to the desired shellcode.

<Gadget1> + <Gadget2> + <Gadget3> + <Gadget4> + <Gadget5> = 1 line of desired assembly instruction(from the target)(i.e `add %rax, %rbx`)

The permutations of these gadgets can create endless possible payloads for each desired assembly instruction.
<Gadget4> + <Gadget5> + <Gadget1> + <Gadget2> + <Gadget3> = A different line of desired assembly.

And of course each gadget's length...

Gadget 1:
> pop %rax
> ret

or 

Gadget 1:
> add %rbx, 4
> pop %rax
> ret

The possiblities are endless. So, the transpiler will try to construct the instructions based on a grouping of gadgets.

gadget_group_1(4+5+1+2+3) === `cmp %rdi,%rax`
gadget_group_2(6+1+6) === `push %rax`
...

and save this internally.

Memoization is our friend here and we will constantly refer back to this internal data-structure for instruction lookup. 

The payload is just an ordering of gadget groups that is the ROP equivalent to the TARGET. 

### ASLR
Another problem to contend with is Address Space Layout Randomization (ASLR).
This defense makes it **impossible** (for the Unaware) for attackers to know
where a particular piece of code/data might reside.
The kernel does this by placing each newly-loaded *section*
at a randomized location.

If an attacker is able to **infer** what those randomized locations might be,
that information can be provided via the `SOURCE:SECTION=BASE` interface.

### Gadget Dependency *(experimental)*
Let's address (pun intended) the elephant in the room:
what if we can't find the desired gadget?

First, let's reduce the problem.
Machine code is (typically) Turing-complete,
so there's not necessarily a canonical way to solve this problem,
or possibly even to go about solving this problem.
Rather than expanding/contracting the input space, let's focus on *rearranging it*.

This makes the **big** assumption that we can represent **all** machine code via a Directed Acyclic Graph (DAG).
Take this x86 *target behavior* (Intel syntax):
```
xor $eax, $eax
pop $rax
add $eax, 4
```

Without further processing, we could directly break this into the following set of gadgets:
```
xor $eax, $eax
ret
...
pop $rax
ret
...
add $eax, 4
ret
...
```

But what if we can't find a gadget ending in `xor $eax, $eax`?
> Remember, this also means any combination ending in `xor $eax, $eax`
> **does not exist**.

Well, we'd have to *reorder the target behavior*,
and we can do this by representing the relationships between instructions as a DAG.
For example: `add $eax, 4` depends on `xor $eax, $eax`'s output, so it **must** come later.

The previous target behavior could be represented as the following DAG:
> start -> (`pop $rax`,
>   `xor $eax, $eax` -> `add $eax, 4`)

This means that so long as `xor $eax, $eax` comes before `add $eax, 4`,
any combination of these can be used as a potential gadget.

If available, this functionality is accessible via the `-a` option.

> **Please note** that even though this makes more gadgets available
> to the transpiler, it is a **resource-consuming** procedure.

### `SOURCE`s
aren't easy to find: there're lots of variables at play.
And the sources are many: the provided `SOURCE`s
and the *full dependency tree* of dynamically-linked libraries for *each* `SOURCE`.

So, why not just look for both?
Well, dynamically-linked libraries can be problematic.

First, let's think about the context of ROP:
it's used *by an attacker*, for bypassing a non-executable stack.
This means that when the attacker generates the ROP payload,
it's (usually) not happening on the target machine.

In Linux, shared libraries are accessible with a name and a version:
for example OpenSSL's `libssl.so.1`.
The linker looks for a file matching `libssl.so.1`, and no farther.

**But**, the program *expects* `libssl.so.1` to be OpenSSL's implementation.
In reality, it could be anything (a common example is LibreSSL's `libssl.so.1`
implementation).
This is a *dynamically linking collision*, and will probably adversely affect our ROP payload.

To mitigate this, we propose the `-r` option;
which makes the recursive search for gadgets
(within dynamically-linked dependencies) just that: optional.

## Resources
http://shell-storm.org/project/ROPgadget/
https://pypi.org/project/capstone/

## Contributing
Bryan
Bailey
Junming

## License
BSD License
