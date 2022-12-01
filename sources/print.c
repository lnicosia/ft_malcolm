#include "../headers/malcolm.h"

void print_ip(int fd, uint8_t *ip_address)
{
	int i = 0;

	while (i < IP_ADDR_LEN) {
		dprintf(fd, "%d", ip_address[i]);
		if (i < IP_ADDR_LEN-1)
			dprintf(fd, ".");
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

static void debug_arp(struct arp_hdr *arp)
{
	printf("_____ARP_____\n");

	/* Type informations */
	printf("Hardware type: %s\n",
		(ft_ntohs(arp->hrd) == HARDWARE_ETHERNET) ? "Ethernet" : "Unknown");
	printf("Protocol type: %s\n",
		(ft_ntohs(arp->pro) == ETH_P_IP) ? "IPv4" : "Unknown");
	printf("Operation: %s\n",
		(ft_ntohs(arp->op) == ARP_REQUEST) ? "ARP Request" : "ARP Reply");

	/* Addresses informations */
	/* Sender */
	printf("Sender MAC: ");
	print_mac(arp->sha);
	printf("\n");
	dprintf(STDOUT_FILENO, "Sender IP: ");
	print_ip(STDOUT_FILENO, arp->sip);
	printf("\n");

	/* Target */
	printf("Target MAC: ");
	print_mac(arp->tha);
	printf("\n");
	dprintf(STDOUT_FILENO, "Target IP: ");
	print_ip(STDOUT_FILENO, arp->tip);
	printf("\n");
}

static void debug_eth(struct ethernet_hdr *ethernet)
{
	printf("_____ETH_____\n");

	/* Type */
	printf("Ethernet type: %s\n",
		(ft_ntohs(ethernet->type) == ETH_P_ARP) ? "ARP" : "Other");

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

void debug_packet(struct ethernet_hdr *ethernet, struct arp_hdr *arp)
{
	debug_eth(ethernet);
	debug_arp(arp);
	printf("_______________________________\n");
}
