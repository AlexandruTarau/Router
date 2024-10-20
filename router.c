#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <string.h>
#include <arpa/inet.h>

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *mac_table;
int mac_table_len;

uint16_t sequence;
uint16_t id;

/* Searches a good match for ip x in the route table */
int binarySearch(uint32_t x, int *l, int r) {
	//int r = rtable_len - 1;

    while (*l <= r) {
        int m = *l + (r - *l) / 2;
 
		if (rtable[m].prefix == (x & rtable[m].mask)) {
			return m;
		}
 
        if (rtable[m].prefix > (x & rtable[m].mask)) {
            *l = m + 1;
		} else {
            r = m - 1;
		}
    }

    return -1;
}

/* Gets best route from route table for ip_dest */
struct route_table_entry *get_best_route(uint32_t ip_dest) {
	// Searches the position of a possible match
	int l = 0, index = binarySearch(ip_dest, &l, rtable_len - 1);
	struct route_table_entry *best_route = (index >= 0 ? &rtable[index] : NULL);

	// Continues searching for a better match to the left of index
	while (index >= 0) {
		index = binarySearch(ip_dest, &l, index - 1);
		if (index >= 0) {
			best_route = &rtable[index];
		}
	}

	return best_route;
}

/* Gets mac entry of given_ip */
struct arp_table_entry *get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}

	return NULL;
}

/* Creates an Ethernet header */
struct ether_header *create_eth_hdr(uint8_t *ether_dhost, uint8_t *ether_shost, uint16_t ether_type) {
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));

	memcpy(eth_hdr->ether_dhost, ether_dhost, 6);
	memcpy(eth_hdr->ether_shost, ether_shost, 6);
	eth_hdr->ether_type = htons(ether_type);

	return eth_hdr;
}

/* Creates an ICMP header */
struct icmphdr *create_icmp_hdr(uint8_t type, uint8_t code) {
	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));

	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->un.echo.id = htons(id++);
	icmp_hdr->un.echo.sequence = htons(sequence++);
	icmp_hdr->checksum = checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr));

	return icmp_hdr;
}

/* Creates an IPv4 header */
struct iphdr *create_ipv4_hdr(uint8_t protocol, uint32_t saddr, uint32_t daddr, struct iphdr *model) {
	struct iphdr *ip_hdr = malloc(sizeof(struct iphdr));

	ip_hdr->protocol = protocol;
	ip_hdr->saddr = saddr;
	ip_hdr->daddr = daddr;
	ip_hdr->frag_off = model->frag_off;
	ip_hdr->ihl = model->ihl;
	ip_hdr->tos = model->tos;
	ip_hdr->ttl = model->ttl;
	ip_hdr->version = model->version;
	ip_hdr->id = htons(id++);
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

	return ip_hdr;
}

/* Creates an ARP header */
struct arp_header *create_arp_hdr(int interface, uint16_t op, uint32_t tpa, uint32_t spa, uint8_t *tha) {
    struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));

    arp_hdr->hlen = 6;	
    arp_hdr->htype = htons(1);
    arp_hdr->op = htons(op);
    arp_hdr->plen = 4;
    arp_hdr->ptype = htons(ETHERTYPE_IP);
	
    memcpy(arp_hdr->tha, tha, sizeof(arp_hdr->tha));
    arp_hdr->tpa = tpa;
    get_interface_mac(interface, arp_hdr->sha);
    arp_hdr->spa = spa;

    return arp_hdr;
}

/* 
 * Sends an ICMP packet of given type:
 * 0  - Echo Reply
 * 3  - Destination Unreachable 
 * 11 - Time Exceeded
 */
void send_icmp(uint8_t type, struct ether_header *eth_hdr, struct iphdr *ip_hdr, int interface, char *buf) {
	struct ether_header *eth = create_eth_hdr(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHERTYPE_IP);
	struct icmphdr *ich = create_icmp_hdr(type, 0);
	struct iphdr *iph = create_ipv4_hdr(1, ip_hdr->saddr, ip_hdr->daddr, ip_hdr);

	// Calculates length of packet
	size_t length = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);
	char buffer[MAX_PACKET_LEN];

	// Fills buffer with packet information
	memcpy(buffer, eth, sizeof(struct ether_header));
	memcpy(buffer + sizeof(struct ether_header), iph, sizeof(struct iphdr));
	memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr), ich, sizeof(struct icmphdr));
	memcpy(buffer + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr), buf + sizeof(struct iphdr) + sizeof(struct ether_header), 8);

	send_to_link(interface, buffer, length);
}

/* 
 * Sends an ARP Reply to interface.
 * eth_hdr - ethernet header of arp request packet
 * arp_hdr - arp header of arp request packet
 */
void send_arp_reply(int interface, struct ether_header *eth_hdr, struct arp_header *arp_hdr) {
	// Creating new ether_header struct
	struct ether_header *eth = create_eth_hdr(eth_hdr->ether_shost, eth_hdr->ether_dhost, ETHERTYPE_ARP);
	get_interface_mac(interface, eth->ether_shost);
	
	// Creating new arp_header struct
	struct arp_header *arh = create_arp_hdr(interface, 2, arp_hdr->spa, inet_addr(get_interface_ip(interface)), arp_hdr->sha);

	// Calculating length of packet
	size_t length = sizeof(struct ether_header) + sizeof(struct arp_header);
	char *buffer = malloc(MAX_PACKET_LEN);

	// Fills buffer with packet information
	memcpy(buffer, eth, sizeof(struct ether_header));
	memcpy(buffer + sizeof(struct ether_header), arh, sizeof(struct arp_header));

	send_to_link(interface, buffer, length);
}

/* Sends an ARP Request on route */
void send_arp_request(struct route_table_entry *route) {
	// Creating new ether_header struct with broadcast destination ip
	uint8_t *mac = malloc(6);
	uint8_t broadcast_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	get_interface_mac(route->interface, mac);
	struct ether_header *eth = create_eth_hdr(broadcast_mac, mac, ETHERTYPE_ARP);

	// Creating new arp_header struct
	uint32_t tpa, spa;
	tpa = route->next_hop;
	spa = inet_addr(get_interface_ip(route->interface));
	struct arp_header *arh = create_arp_hdr(route->interface, 1, tpa, spa, broadcast_mac);

	// Determining length of packet
	size_t length = sizeof(struct ether_header) + sizeof(struct arp_header);
	char buffer[MAX_PACKET_LEN];

	// Assembling packet
	memcpy(buffer, eth, sizeof(struct ether_header));
	memcpy(buffer + sizeof(struct ether_header), arh, sizeof(struct arp_header));

	send_to_link(route->interface, buffer, length);
}

/* Compare function for qsort */
int compare (const void *entry1, const void *entry2) {
	uint32_t pe1 = ((struct route_table_entry *) entry1)->prefix;
	uint32_t pe2 = ((struct route_table_entry *) entry2)->prefix;
	uint32_t me1 = ((struct route_table_entry *) entry1)->mask;
	uint32_t me2 = ((struct route_table_entry *) entry2)->mask;
	if(pe1 == pe2) {
		return (int)(me2 - me1);
	} else {
		return (int)(pe2 - pe1);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	queue q = queue_create();
	size_t qlen = 0;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Code to allocate the MAC and route tables
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(rtable == NULL, "memory");

	mac_table = malloc(sizeof(struct  arp_table_entry) * 100000);
	DIE(mac_table == NULL, "memory");
	
	// Read and sort the static routing table
	rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare);

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// We receive an IPv4 packet
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Echo Reply
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)) && ip_hdr->protocol == 1) {
				send_icmp(0, eth_hdr, ip_hdr, interface, buf);
				continue;
			}

			// Check the ip_hdr integrity using checksum
			uint16_t check = ip_hdr->check;
			ip_hdr->check = 0;
			if (check != htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))) {
				continue;
			}
			ip_hdr->check = check;

			/* Call get_best_route to find the most specific route.
			Send "Destination unreachable" icmp if null */
			struct route_table_entry *route = get_best_route(ip_hdr->daddr);
			if (!route) {
				send_icmp(3, eth_hdr, ip_hdr, interface, buf);
				continue;
			}

			/* Check TTL > 1. Update TLL. Update checksum.
			Send "Time exceeded" icmp if TTL expires */
			if (ip_hdr->ttl > 1) {
				ip_hdr->check = ~(~ip_hdr->check + ~((uint16_t)ip_hdr->ttl) + (uint16_t)(ip_hdr->ttl - 1)) - 1;
				ip_hdr->ttl--;
			} else {
				send_icmp(11, eth_hdr, ip_hdr, interface, buf);
				continue;
			}

			/* Search the destination MAC address. If not found,
			send ARP Request to interogate about the mac of next hop */
			struct arp_table_entry *mac_entry = get_mac_entry(route->next_hop);
			if (!mac_entry) {
				send_arp_request(route);

				// Enqueue current packet
				char *stored_buf = malloc(MAX_PACKET_LEN);
                memcpy(stored_buf, buf, len);
				queue_enq(q, stored_buf);
				qlen++;
				continue;
			}

			// Update the ethernet addresses
			uint8_t *mac = malloc(6);
			get_interface_mac(route->interface, mac);
			memcpy(buf, mac_entry->mac, 6);
			memcpy(buf + 6, mac, 6);

			// Send packet to the next interface
			send_to_link(route->interface, buf, len);

			// We receive an ARP packet
		} else if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			switch (ntohs(arp_hdr->op)) {
				case 1: { // ARP Request
					// Reply to request
					send_arp_reply(interface, eth_hdr, arp_hdr);
					break;
				}
				case 2: { // ARP Reply
					// Adding entry in mac table
					mac_table[mac_table_len].ip = arp_hdr->spa;
					memcpy(mac_table[mac_table_len].mac, arp_hdr->sha, 6);
					mac_table_len++;

					// Sending enqueued packets
					size_t aux = qlen;
					for (int i = 0; i < aux; i++) {
						// Extract first packet from queue
						char *buffer = queue_deq(q);
						struct ether_header *eth = (struct ether_header *)buffer;
						struct iphdr *iph = (struct iphdr *)(buffer + sizeof(struct ether_header));
						struct route_table_entry *route = get_best_route(iph->daddr);

						// If there is a route we send the packet
						if (route != NULL) {
							get_interface_mac(route->interface, eth->ether_shost);
							memcpy(eth->ether_dhost, arp_hdr->sha, 6);
							eth->ether_type = ntohs(ETHERTYPE_IP);

							// Calculating length of packet
							size_t len = sizeof(struct ether_header) + ntohs(iph->tot_len);

							send_to_link(route->interface, buffer, len);
							qlen--;
						} else {
							// If there is no route, we put the packet back in queue
							queue_enq(q, buffer);
						}
					}
					break;
				}
			}
		}
	}

	free(rtable);
	free(mac_table);
	return 0;
}

