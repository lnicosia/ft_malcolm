#include "malcolm.h"

void print_ip(uint8_t *ip_address)
{
	int i = 0;

	while (i < IP_ADDR_LEN) {
		printf("%d", ip_address[i]);
		if (i < IP_ADDR_LEN-1)
			printf(".");
		i++;
	}
}

void print_mac(uint8_t *mac)
{
	int i = 0;

	while (i < ETH_ADDR_LEN) {
		printf("%02X", mac[i]);
		if (i < ETH_ADDR_LEN-1)
			printf(":");
		i++;
	}
}

void debug_arp(struct arp_hdr *arp)
{
	printf("_____ARP_____\n");

	/* Type informations */
	printf("Hardware type: %s\n",
		(ntohs(arp->hrd) == HARDWARE_ETHERNET) ? "Ethernet" : "Unknown");
	printf("Protocol type: %s\n",
		(ntohs(arp->pro) == ETH_P_IP) ? "IPv4" : "Unknown");
	printf("Operation: %s\n",
		(ntohs(arp->op) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

	/* Addresses informations */
	/* Sender */
	printf("Sender MAC: ");
	print_mac(arp->sha);
	printf("\n");
	printf("Sender IP: ");
	print_ip(arp->sip);
	printf("\n");

	/* Target */
	printf("Target MAC: ");
	print_mac(arp->tha);
	printf("\n");
	printf("Target IP: ");
	print_ip(arp->tip);
	printf("\n");
}

void debug_eth(struct ethernet_hdr *ethernet)
{
	printf("_____ETH_____\n");

	/* Type */
	printf("Ethernet type: %s\n",
		(ntohs(ethernet->type) == ETH_P_ARP) ? "ARP" : "Other");

	/* Addresses informations */
	/* Sender */
	printf("Sender MAC: ");
	print_mac(ethernet->smac);
	printf("\n");

	/* Target */
	printf("Target MAC: ");
	print_mac(ethernet->dmac);
	printf("\n");
}

void debug_packet(char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ntohs(ethernet->type);

	if (type == ETH_P_ARP) {
		printf("\n");
		debug_eth(ethernet);
		debug_arp(arp);
		printf("_______________________________\n");
	}
}

int ft_malcolm(void)
{
	int sockfd;
	int len = sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr);
	char buffer[len];
	int ret;

	/* Socket creation */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		fprintf(stderr, "[!] Failed to create socket\n");
		return 1;
	}

	printf("Sniffing ARP packets...\n");
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
