Tarău Alexandru-Bogdan
322CC

# Dataplane Router

This is a simple implementation of a dataplane router in C. The router utilizes a static routing table and an Address Resolution Protocol (ARP) table to forward packets received on one interface to another interface based on the destination IP address.

## Features

- **Static Routing**: The router uses a static routing table to determine the best route for forwarding packets based on destination IP addresses. This is made efficient using Binary Search.<br><br>
- **Address Resolution Protocol (ARP)**: The router uses ARP to map IP addresses to MAC addresses. By generating
a broadcast message the router can find the mac address based on the ip of the next hop.<br><br>
- **ICMP Handling**: The router handles Internet Control Message Protocol (ICMP) messages, including Echo Reply, Destination Unreachable, and Time Exceeded messages.<br><br>
- **Checksum Verification**: Checks the integrity of the IP header using a checksum calculation.

## Implementation Details

- *get_best_route*: Using Binary Search searches for a possible match for the destination ip. Then repeatedly uses bsearch each time tightening the interval approaching the beginning of the table in search for the best match.<br><br>

- *get_mac_entry*: Searches the given ip in the mac table.<br><br>

- *create_eth_hdr*: Creates an Ethernet Header with given parameters.<br><br>

- *create_icmp_hdr*: Creates an ICMP Header with given parameters.<br><br>

- *create_ipv4_hdr*: Creates an IPv4 Header with given parameters using an already existing ip header as model.<br><br>

- *create_arp_hdr*: Creates an ARP Header with given parameters. The sender hardware address(sha) will be the mac of the interface.<br><br>

- *send_icmp*: Handles all ICMP type packets to be sent. In our case we have:
  * Echo Reply
  * Destination Unreachable 
  * Time Exceeded
The function requires information about the received packet to build the new one to send.<br><br>

- *send_arp_reply*: Using information about the arp request packet, we create a new packet as response to send our own information(mac addresses).<br><br>

- *send_arp_request*: We broadcast an ARP Request hoping to find the mac address of the next hop.<br><br>

- *main*: We receive a packet and store it in a buffer. Depending on the type of protocol used we decide what to do with the packet:<br><br>
    * *IPv4*: If the packet is directed to the router we send an Echo Reply. Else, we check the integrity of the ip header. We find the best route toward the destination. If there is no such route we send a "Destination unreachable" message. We check if the time allocated for the packet has expired. If yes, a "Time exceeded" message is sent. Else, we update the checksum and ttl. Then, we search for the mac address of the next hop and forward the packet to the next location if the address is found. If not, we send an ARP Request and store the packet for later.<br><br>
    * *ARP*: Depending on what command we receive, we either:
        * Send an ARP Reply in case we get an ARP Request.
        * Add a new entry in the mac table and send queued packets if a route is found in case we get an ARP Reply.
