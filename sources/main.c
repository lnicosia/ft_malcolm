#include "malcolm.h"

void print_ip(uint32_t ip_address)
{
	unsigned char byte[4]  = {0,0,0,0};
	int i = 0;
	while (i < 4) {
		byte[i] = (ip_address >> (i*8)) & 0xFF;
		printf("%d:", byte[i]);
		i++;
	}
	printf("\n");
}

void debug_packet(char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ntohs(ethernet->ether_type);

	if (type == ETHERTYPE_ARP) {
		printf("==Received an ARP request==\n");
		print_ip(arp->ar_tip);
		printf("= opcode: %d\n", htons(arp->ar_op));
		printf("===========================\n");
	}
}

int ft_malcolm(void)
{
	int sockfd;
	unsigned int len = 9999; // sizeof struct arp_packet
	char buffer[len];
	int ret;

	/* Socket creation */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		fprintf(stderr, "[!] Failed to create socket\n");
		return 1;
	}

	while ((ret = recv(sockfd, buffer, len, 0)) != -1) {
		if (ret > 0)
			debug_packet(buffer);
	}

	close(sockfd);

	return 0;
}

int main(int ac, char **av)
{
	(void)ac;
	(void)av;
	ft_malcolm();
	return 0;
}
