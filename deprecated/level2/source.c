#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STACK_ADDR_RANGE_START 0xb0000000 

char *p()
{
	// 4 bytes alignment
	void* comp_value __attribute__((aligned(4)));
	char  buf[64];

	fflush(stdout);
	gets(buf);
	comp_value = __builtin_return_address(0);
	if (((int)comp_value & STACK_ADDR_RANGE_START) == STACK_ADDR_RANGE_START)
	{
		printf("%p\n", __builtin_return_address(0));
		exit(1);
	}
	puts(buf);
	return strdup(buf);
}

int main()
{
	p();
	return 0;
}
