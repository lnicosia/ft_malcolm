#include "malcolm.h"

void debug_packet(char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ntohs(ethernet->ether_type);

	printf("type: %d\n", type);
	printf("arp op: %d\n", arp->ar_op);
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
