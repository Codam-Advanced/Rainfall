#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv)
{
	int numb;

	numb = atoi(argv[1]);
	if (numb == 423)
	{
		char* cmd = strdup("/bin/sh");
		char*argv[2] = { cmd, NULL };

		gid_t egid = getegid();
		uid_t euid = geteuid();

		setegid(egid);
		seteuid(euid);

		execve(cmd, argv, NULL);
	}
	else
	{
		write(1, "No !\n", 5);
	}
	return 0;
}