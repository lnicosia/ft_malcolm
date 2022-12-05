#include "../headers/malcolm.h"
#include <netdb.h>

void print_ip(int fd, uint8_t *ip_address)
{
	static char	host[512];
	struct sockaddr_in	addr;

	ft_bzero(host, sizeof(host));
	ft_bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	ft_memcpy(&addr.sin_addr, ip_address, sizeof(addr.sin_addr));
	if (getnameinfo((struct sockaddr*)&addr, sizeof(struct sockaddr),
			host, sizeof(host), NULL, 0, 0))
		dprintf(fd, "%s", inet_ntoa(addr.sin_addr));
	else
		dprintf(fd, "%s (%s)", host, inet_ntoa(addr.sin_addr));
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
