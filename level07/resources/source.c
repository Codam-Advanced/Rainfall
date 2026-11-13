#include <stdio.h>

void print_banner();
void process_packet();
void dump_packets();
void calc_checksum();

int packet_count;

void route_tag()
{
	char buf[128];

	printf("[SPRAWL] Route tag: ");
	fflush(stdout);

	if (fgets(buf, 128, stdin) == NULL)
	{
		// Stack check

		return ;
	}

	printf("[SPRAWL] Routing via ");
	printf(buf);

	fflush(stdout);

	// Stack check

	return ;
}

typedef struct packet_header_t {
	unsigned int fingerprint;
	short int size;
	short int count;
}	header_t;

int read_header(header_t *header)
{
	header_t *ptr = header;

	printf("[SPRAWL] Header (hex): ");
	fflush(stdout);

	if (scanf("%x %hx %hx", &ptr->fingerprint, &ptr->size, &ptr->count) != 3)
	{
		return -1;
	}

	if (ptr->fingerprint == 0xdeadbeef)
	{
		return 0;
	}

	return -1;
}

void process_packet()
{
	char replay_buffer[64]; // -0x50
	int checksum; // 0x54
	header_t header; // -0x56 through -0x5c, 0x5c is fingerprint, 0x58 is size, 0x56 is count 
	short int size; // -0x68
	short int frame_size; // -0x6a

	if (read_header(&header) < 0)
	{
		puts("[SPRAWL] Invalid header.");

		// Stack check

		return ;
	}

	frame_size = ((int)header.count * (int)header.size);

	if (frame_size > 64)
	{
		puts("[SPRAWL] Frame too large for relay buffer.");

		return ;
	}

	size = header.size;

	printf("[SPRAWL] Transmit (%u bytes): ", frame_size);
	fflush(stdout);

	getchar();

	fread(replay_buffer, 1, size, stdin);

	if (frame_size > 64)
		calc_checksum(replay_buffer, 64);
	else
		calc_checksum(replay_buffer, frame_size);

	if (packet_count <= 31)
	{
		// Save packet info into global var

		packet_count++;
	}

	printf("[SPRAWL] Packet %u received. Checksum: %08x\n", packet_count, checksum);
}

int main()
{

	print_banner();
	route_tag();
	process_packet();
	dump_packets();

	return 0;
}
