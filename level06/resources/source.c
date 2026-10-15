#include <stdio.h>
#include <string.h>

void	init_vault(void);
void	print_banner(void);
void	log_request(void);
void	authenticate(void);
void	display_vault(void);

void log_request()
{
	char buf[64];

	printf("[3JANE] Request ID: ");
	fflush(stdout);
	fgets(buf, 64, stdin);

	buf[strcspn(buf, "\n") + 1] = '\0';

	printf("[3JANE] Logging: ");
	printf(buf);
	putchar("\n");

	// store access_log_idx into global variable

	// stack check

	return ;
}

typedef struct vault_s {
	int num1;
	unsigned int num2;
}	vault_t;

vault_t vault;

void authenticate()
{
	char buf[128];

	printf("[3JANE] Access code: ");
	fflush(stdout);
	gets(buf);

	if (strncmp(buf, "STRAYLIGHT_", 11) != 0)
	{
		printf("[3JANE] Access granted. Clearance level: %u\n", vault.num2);
	} else {
		puts("[3JANE] Access denied.");
	}

	// stack check

	return ;
}

int main()
{
	init_vault();
	print_banner();
	log_request();
	authenticate();
	display_vault();

	// stack check

	return 0;
}
