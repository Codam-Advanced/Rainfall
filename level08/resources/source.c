#include <stdio.h>
#include <stdlib.h>
#include <cstdint>

void init_routing();
void print_banner();
void add_route(char *route_name, char *gateway, int hops);
void print_routes();

char relay_buf[512];
ssize_t relay_len;

void relay_status()
{
	char buf[64]; // 0x50
	ssize_t bytes_read; // 0x58
	// padding 2 bytes 0x60

	// 0x00000000004014ec
	printf("[MAELCUM] Tag this relay (who's asking?): ");

	fflush(stdout);

	bytes_read = read(0, &buf, 63);

	// if read return negative set bytes_read to 0
	if (bytes_read < 0)
		bytes_read = 0;

	// remove the \n from the buffer move the \0
	buf[strcspn(&buf, "\n")] = '\0';

	printf("[MAELCUM] Logging relay tag: ");
	
	// very safe lol
	printf(&buf);

	// add da newline
	putchar('\n');

	// flush da out
	fflush(stdout);

	// canary
}

void relay_data()
{
	// 8 bytes for stack canary -0x8
	// 8 unused bytes?, padding/alignment
	char buf[32]; // -0x30
	unsigned long bytes_to_read; // -0x34
	// 12 bytes padding/alignment

	printf("[MAELCUM] Send it: ");
	fflush(stdout);

	read(0, buf, 64);

	if (strncmp(buf, "RELAY:", 6) != 0)
	{
		puts("[MAELCUM] Unknown command.");
		// stack check
		return;
	}

	bytes_to_read = strtoul(&buf[6], NULL, 10);

	if (bytes_to_read > 0x1ff)
	{
		// stack check
		return ;
	}

	printf("[MAELCUM] Ready for %u bytes: ", bytes_to_read);
	fflush(stdout);

	relay_len = read(0, relay_buf, bytes_to_read);
	printf("[MAELCUM] Relayed %u bytes.\n", relay_len);

	// stack check
	return;
}

int main()
{
	init_routing();
	print_banner();
	add_route("FREESIDE", "GATEWAY_3", 3);
	add_route("VILLA_STRAYLIGHT", "TESSIER_GW", 5);
	relay_status();
	relay_data();
	print_routes();

	// stack check
	return 0;
}

