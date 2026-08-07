#define _GNU_SOURCE

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	if (atoi(argv[1]) == 423)
	{
		char* cmd = strdup("/bin/sh");
		char* arguments[2] = { cmd, NULL };

		gid_t egid = getegid();
		uid_t euid = geteuid();

		setresgid(egid, egid, egid);
		setresuid(euid, euid, euid);

		execve("/bin/sh", arguments, NULL);
	}
	else
	{
		fwrite("No !\n", 5, 1, stderr);
	}
	return 0;
}
