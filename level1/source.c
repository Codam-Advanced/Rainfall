#include <stdio.h>
#include <stdlib.h>

void run()
{
	fwrite("Good... Wait what?\n", 19, 1, stdout);
	system("/bin/sh");
}

int main()
{
	char input[64];

	return (int)gets(input);
}
