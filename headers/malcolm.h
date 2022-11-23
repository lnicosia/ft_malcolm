#ifndef MALCOLM_H
# define MALCOLM_H

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <unistd.h>

#define ETH_ADDR_LEN 6
#define ETHERTYPE_ARP 0x0806

/* Ethernet header */
struct ethernet_hdr {
	u_char ether_dmac[ETH_ADDR_LEN]; /* destination mac address */
	u_char ether_smac[ETH_ADDR_LEN]; /* source mac address */
	u_int16_t ether_type; /* ethertype: arp, rarp, ip ... */
};

/* Ethernet ARP packet from RFC 826 */
struct arp_hdr {
	uint16_t ar_hrd; /* Format of hardware address */
	uint16_t ar_pro; /* Format of protocol address */
	uint8_t ar_hln; /* Length of hardware address */
	uint8_t ar_pln; /* Length of protocol address */
	uint16_t ar_op; /* ARP opcode (command) */
	uint8_t ar_sha[ETH_ALEN]; /* Sender hardware address */
	uint32_t ar_sip; /* Sender IP address */
	uint8_t ar_tha[ETH_ALEN]; /* Target hardware address */
	uint32_t ar_tip; /* Target IP address */
};

#endif
