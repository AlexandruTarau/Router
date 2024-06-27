#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "list.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>


#define ETHERTYPE_IP 0x0800

//check if the mac adress of the destination is the same with the interface mac adreess
int check_mac_address(uint8_t *interface_mac, uint8_t *destination_mac){// nu stiu daca tipul varibilelor e la fel
int i;

	for( i = 0; i <  6; i++){
		if(interface_mac[i] != destination_mac[i])
			return 0;
	}
	return 1;
}
//am facut cautarea mai eficineta folsind algoritmul divide et impera
// void ip_longest_prefix_match (list rtable_list, uint32_t ip_adress){

// }

list making_a_list_from_rtable(struct route_table_entry *rtable, int rtable_lenghth){

	list rtable_list = NULL ;
	int i;
	
	for(i = 0; i < rtable_lenghth; i++){
		rtable_list = cons(&rtable [i] , rtable_list);
	}
	return rtable_list;



}
struct route_table_entry* get_best_route(uint32_t ip_dest, struct route_table_entry *rtable, int rtable_len)
{
	/* TODO 2.2: Implement the LPM algorithm */
	/* We can iterate through rtable for (int i = 0; i < rtable_len; i++). Entries in
	 * the rtable are in network order already */
	struct route_table_entry* best_entry = NULL;

	for (int i = 0; i < rtable_len; i++) {
		if (rtable[i].prefix == (ip_dest & rtable[i].mask) &&
			(best_entry == NULL || best_entry->prefix < rtable[i].prefix)) {
			best_entry = &rtable[i];
		}
	}

	return best_entry;
}
struct arp_table_entry* get_mac_adress_of_arp_table (uint32_t ip_dest, struct arp_table_entry *arp_table, int arp_table_len)
{
	
	struct route_table_entry* mac_adress_of_best_route = NULL;

	for (int i = 0; i < arp_table_len; i++) 

		if(arp_table[i].ip == ip_dest)
			return &arp_table[i];

	return NULL;
}
int functie_sortare(const void *a, const void *b) {
    
    const struct route_table_entry *entry1 = (const struct route_table_entry *)a;
    const struct route_table_entry *entry2 = (const struct route_table_entry *)b;

    
    if (entry1->mask != entry2->mask) {
        return entry2->mask - entry1->mask;
    }

    
    return entry2->prefix - entry1->prefix;
}




int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	printf("cerc");
	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *rtable = (struct route_table_entry *)malloc( sizeof ( struct route_table_entry ) * 100000 );//creating readtbale 
	int rtable_lenght = read_rtable( argv[1],  rtable) ;
	qsort( rtable, rtable_lenght, sizeof(struct route_table_entry), functie_sortare);
	// list route_table_list = making_a_list_from_rtable ( rtable, rtable_lenght );

	struct arp_table_entry* arp_table = NULL;
	int arp_table_length = 0;

	arp_table =(struct  arp_table_entry *) malloc(sizeof(struct  arp_table_entry) * 1000000);
	arp_table_length = parse_arp_table( "arp_table.txt" , arp_table);

	
printf("\n \n \n marius\n");

	while (1) {


		int interface;
		size_t len;

		printf("\n \n \n ccrevete\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("\n \n \n negare\n");
		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		
		


		// uint8_t *interface_mac = malloc(sizeof (uint8_t));
		// get_interface_mac( interface, interface_mac);//preaiu adresa mac a interfetei
		
		//if	( check_mac_address ( interface_mac, eth_hdr->ether_dhost ) == 1 ){ // am tratat doar cazul in care adresa destinatie a intefetei si a destinatei e la fel
							//mai e un caz de tratat
			//printf("trece pe aici \n");
			//printf(ntohs (eth_hdr -> ether_type ))
			
			
			if ( ntohs (eth_hdr -> ether_type ) == ETHERTYPE_IP ){
				 

								struct iphdr *ip_hdr = (struct iphdr*)(buf + sizeof(struct ether_header));
								// uint16_t verify_checksum = checksum((uint16_t*)ip_hdr , sizeof(struct iphdr));

								// check if the this router is the destination 
								uint32_t interface_ip = inet_addr(get_interface_ip(interface));

								if ( ntohs (ip_hdr -> daddr )  == interface_ip) // aici am pus putin diferit, invers chair fata de de ce credeam ca trebuie inainte :))
									continue;

								else {
									//verific daca pachetele au fost corupte prin intermediul checksumului 
									uint16_t previous_checksum = ntohs (ip_hdr -> check); 
									ip_hdr -> check = 0;

									if (checksum((void*) ip_hdr , sizeof(struct iphdr)) == previous_checksum){
										

										struct route_table_entry *next_hop_rtable =  get_best_route(ip_hdr -> daddr, rtable, rtable_lenght);

											if (next_hop_rtable != NULL){
										
												if (ip_hdr->ttl > 1){
													
													ip_hdr->check = 0;
													ip_hdr->ttl --;
													ip_hdr->check = htons(checksum((void *)ip_hdr, sizeof(struct iphdr)));
													struct arp_table_entry *mac_adress_of_next_hop =  get_mac_adress_of_arp_table(next_hop_rtable -> next_hop, arp_table, arp_table_length);
													if (mac_adress_of_next_hop == NULL ){
														continue;
													 }
													
													memcpy(eth_hdr->ether_dhost, mac_adress_of_next_hop -> mac , sizeof(eth_hdr->ether_dhost));////???????

													get_interface_mac(next_hop_rtable->interface, eth_hdr->ether_shost);
													send_to_link(next_hop_rtable -> interface, buf, len);

												}
												else{
													printf("Time exceeded \n");
												}

											}
											else{
												printf("Destination unreachable \n");
											}

									}
									else {
										printf("checksum_invalid \n");
									}
								}
								
				

			
			}
		//}
		// else {
		// 	printf("Destination unreachable \n");
		// }


	}
	free(arp_table);
	free(rtable);
			

}