#include <stdlib.h>
#include <stdio.h>

void lol(void)
{
	syscall(0x80);
}



int main()
{
	char buf[32];
	gets(buf);
	printf("%s\n",buf);
	return 0;
}
