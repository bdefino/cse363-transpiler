#include <stdlib.h>
#include <stdio.h>

int main()
{
	char buf[32];
	gets(buf);
	printf("%s\n",buf);
	return 0;
}
