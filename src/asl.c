/*
 *  ARP Stealth Listener (ASL) v1.0
 *  Copyright (C) 2012 Sipera VIPER Lab - Jason Ostrom
 *
 *  This file is part of ARP Stealth Listener (ASL).
 *
 *  ASL is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  ASL is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *                                                                                                                 
 **/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>
#include "asl.h"
#define ETH_HEADER_SIZE 14

char *device;
pcap_t *handle;
int host_count_n = 0;
int host_count_d = 0;
int packet_count_d = 0;
int packet_count_n = 0;
int compareval = 0;
FILE *ofile;
FILE *ofile2;
FILE *myassfile1;

// From main.c
extern int debug_yes;
extern char *IfName_temp;

// From ass.c
extern int toggle_arp_sniffer_d_yes;
extern int toggle_arp_sniffer_n_yes;
extern char *vinterfaceTmp;

struct macip addressbuff_d[65535];
struct macip addressbuff_n[65535];

void ctrl_c () {
	printf("Exiting\n");
	pcap_breakloop (handle);
	pcap_close(handle);
	exit (0);
}

void sourcecopy (struct ether_arp *arp_temppack, struct macip *mymacip) {

	//mymacip = (struct macip *)malloc(sizeof(struct macip));

	mymacip->mac[0] = arp_temppack->arp_sha[0];
	mymacip->mac[1] = arp_temppack->arp_sha[1];	
	mymacip->mac[2] = arp_temppack->arp_sha[2];	
	mymacip->mac[3] = arp_temppack->arp_sha[3];
	mymacip->mac[4] = arp_temppack->arp_sha[4];	
	mymacip->mac[5] = arp_temppack->arp_sha[5];

	mymacip->ip[0] = arp_temppack->arp_spa[0];
	mymacip->ip[1] = arp_temppack->arp_spa[1];
	mymacip->ip[2] = arp_temppack->arp_spa[2];
	mymacip->ip[3] = arp_temppack->arp_spa[3];

	//return tempmacip;
}

void output_file (struct ether_arp *arp_temppack, int filearg) {

	int i;
	int flush;

	for( i = 0; i < 6; i++ ){

		//fprintf(ofile, "%02x",arp_temppack->arp_sha[i]);
		if (filearg == 1) {
			fprintf(ofile2, "%02x",arp_temppack->arp_sha[i]);
			flush = fflush(ofile2);
		
			if( i < 5) {
				fprintf(ofile2, ":");
				flush = fflush(ofile2);
			} else {
				fprintf(ofile2, ",");
				flush = fflush(ofile2);
			}
		} else if (filearg == 0) {

                        fprintf(ofile, "%02x",arp_temppack->arp_sha[i]);
			flush = fflush(ofile);

                        if( i < 5) {
                                fprintf(ofile, ":");
				flush = fflush(ofile);
                        } else {
                                fprintf(ofile, ",");
				flush = fflush(ofile);
                        }

		}

	}

	for( i = 0; i < 4; i++ ){

		if(filearg == 1) {

			fprintf(ofile2, "%d",arp_temppack->arp_spa[i]);
			flush = fflush(ofile2);

			if ( i < 3 ) {
				fprintf(ofile2, ".");
				flush = fflush(ofile2);
			} else {
				fprintf(ofile2, "\n");
				flush = fflush(ofile2);
			}

		} else if (filearg == 0) {

                        fprintf(ofile, "%d",arp_temppack->arp_spa[i]);
			flush = fflush(ofile);

                        if ( i < 3 ) {
                                fprintf(ofile, ".");
				flush = fflush(ofile);
                        } else {
                                fprintf(ofile, "\n");
				flush = fflush(ofile);
                        }

		}
	}

}
int packetcompare_d (struct ether_arp *arp_temppack) {

	int x = 1;
	int a;
	int samemaccount;
	int sameipccount;
	int samecounto = 0;
	int diffcount;
	int diffcounto = 0;

	for (a = 0; a < host_count_d; a++) {
		int samemaccount = 0;
		int sameipcount = 0;
		int diffcount = 0;

		//printf("Looping ARP packet: %d of packet count: %d\n",a,packet_count);

		if (addressbuff_d[a].mac[0] == arp_temppack->arp_sha[0]) {
			//same byte 1 of mac address
			samemaccount++;
			//printf("Same byte 1, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[0],arp_temppack->arp_sha[0]);
		} else {
			diffcount++;
			//printf("Different byte 1, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[0],arp_temppack->arp_sha[0])
; 
		}
		if (addressbuff_d[a].mac[1] == arp_temppack->arp_sha[1]) {
			//same byte 2 of mac address
			samemaccount++;
			//printf("Same byte 2, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[1],arp_temppack->arp_sha[1]);
		} else {
			diffcount++;
			//printf("Different byte 2, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[1],arp_temppack->arp_sha[1])
; 
		}
		if (addressbuff_d[a].mac[2] == arp_temppack->arp_sha[2]) {
			//same byte 3 of mac address
			samemaccount++;
			//printf("Same byte 3, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[2],arp_temppack->arp_sha[2]);
		} else {
			diffcount++;
			//printf("Different byte 3, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[2],arp_temppack->arp_sha[2])
; 
		}
		if (addressbuff_d[a].mac[3] == arp_temppack->arp_sha[3]) {
			//same byte 4 of mac address
			samemaccount++;
			//printf("Same byte 4, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[3],arp_temppack->arp_sha[3]);
		} else{
			diffcount++;
			//printf("Different byte 3, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[3],arp_temppack->arp_sha[3])
; 
		}
		if (addressbuff_d[a].mac[4] == arp_temppack->arp_sha[4]) {
			//same byte 5 of mac address
			samemaccount++;
			//printf("Same byte 5, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[4],arp_temppack->arp_sha[4]);
		} else {
			diffcount++;
			//printf("Different byte 5, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[4],arp_temppack->arp_sha[4])
; 
		}
		if (addressbuff_d[a].mac[5] == arp_temppack->arp_sha[5]) {
			//same byte 6 of mac address
			samemaccount++;
			//printf("Same byte 6, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[5],arp_temppack->arp_sha[5]);
		} else {
			diffcount++;
			//printf("Different byte 6, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[5],arp_temppack->arp_sha[5])
; 
		}	
		if (addressbuff_d[a].ip[0] == arp_temppack->arp_spa[0]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_d[a].ip[1] == arp_temppack->arp_spa[1]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_d[a].ip[2] == arp_temppack->arp_spa[2]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_d[a].ip[3] == arp_temppack->arp_spa[3]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		
		if (samemaccount ==  6) {
			samecounto++;
			//printf("Host ARP packet source MAC seen before, setting samecounto to %d\n",samecounto);
		} else {
			diffcounto++;
			//printf("Host ARP Packet source MAC not seen before, setting diffcounto to %d: samemaccount: %d  diffcount: %d\n",diffcounto,samemaccount,diffcount);
		}

	}

	if (samecounto == 1) {
		//All host packets seen before
		x = 1;
		//printf("Host packet seen before: packet_count: %d, samecounto: %d, diffcounto: %d, returning x: %d\n",packet_count,samecounto,diffcounto,x);

	} else {
		x = 0;
		//printf("Host packet Not seen before: packet_count: %d, samecounto: %d, diffcounto: %d, returning x: %d\n",packet_count,samecounto,diffcounto,x);
	}
	return x;

}
int packetcompare_n (struct ether_arp *arp_temppack) {

	int x = 1;
	int a;
	int samemaccount;
	int sameipccount;
	int samecounto = 0;
	int diffcount;
	int diffcounto = 0;

	//for (a = 0; a < packet_count_n; a++) {
	for (a = 0; a < host_count_n; a++) {
		int samemaccount = 0;
		int sameipcount = 0;
		int diffcount = 0;

		//printf("Looping ARP packet: %d of packet count: %d\n",a,packet_count);

		if (addressbuff_n[a].mac[0] == arp_temppack->arp_sha[0]) {
			//same byte 1 of mac address
			samemaccount++;
			//printf("Same byte 1, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[0],arp_temppack->arp_sha[0]);
		} else {
			diffcount++;
			//printf("Different byte 1, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[0],arp_temppack->arp_sha[0]); 
		}
		if (addressbuff_n[a].mac[1] == arp_temppack->arp_sha[1]) {
			//same byte 2 of mac address
			samemaccount++;
			//printf("Same byte 2, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[1],arp_temppack->arp_sha[1]);
		} else {
			diffcount++;
			//printf("Different byte 2, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[1],arp_temppack->arp_sha[1]); 
		}
		if (addressbuff_n[a].mac[2] == arp_temppack->arp_sha[2]) {
			//same byte 3 of mac address
			samemaccount++;
			//printf("Same byte 3, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[2],arp_temppack->arp_sha[2]);
		} else {
			diffcount++;
			//printf("Different byte 3, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[2],arp_temppack->arp_sha[2]); 
		}
		if (addressbuff_n[a].mac[3] == arp_temppack->arp_sha[3]) {
			//same byte 4 of mac address
			samemaccount++;
			//printf("Same byte 4, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[3],arp_temppack->arp_sha[3]);
		} else{
			diffcount++;
			//printf("Different byte 3, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[3],arp_temppack->arp_sha[3]); 
		}
		if (addressbuff_n[a].mac[4] == arp_temppack->arp_sha[4]) {
			//same byte 5 of mac address
			samemaccount++;
			//printf("Same byte 5, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[4],arp_temppack->arp_sha[4]);
		} else {
			diffcount++;
			//printf("Different byte 5, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[4],arp_temppack->arp_sha[4]); 
		}
		if (addressbuff_n[a].mac[5] == arp_temppack->arp_sha[5]) {
			//same byte 6 of mac address
			samemaccount++;
			//printf("Same byte 6, incrementing samecount to %d: %02x vs. %02x\n",samecount,addressbuff[a].mac[5],arp_temppack->arp_sha[5]);
		} else {
			diffcount++;
			//printf("Different byte 6, incrementing diffcount to %d: %02x vs. %02x\n",diffcount,addressbuff[a].mac[5],arp_temppack->arp_sha[5]); 
		}	
		if (addressbuff_n[a].ip[0] == arp_temppack->arp_spa[0]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_n[a].ip[1] == arp_temppack->arp_spa[1]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_n[a].ip[2] == arp_temppack->arp_spa[2]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		if (addressbuff_n[a].ip[3] == arp_temppack->arp_spa[3]) {
			sameipcount++;
		} else {
			diffcount++;
		}
		
		if (samemaccount ==  6) {
			samecounto++;
			//printf("Host ARP packet source MAC seen before, setting samecounto to %d\n",samecounto);
		} else {
			diffcounto++;
			//printf("Host ARP Packet source MAC not seen before, setting diffcounto to %d: samemaccount: %d  diffcount: %d\n",diffcounto,samemaccount,diffcount);
		}

	}

	if (samecounto == 1) {
		//All host packets seen before
		x = 1;
		//printf("Host packet seen before: packet_count: %d, samecounto: %d, diffcounto: %d, returning x: %d\n",packet_count,samecounto,diffcounto,x);
	} else {
		x = 0;
		//printf("Host packet Not seen before: packet_count: %d, samecounto: %d, diffcounto: %d, returning x: %d\n",packet_count,samecounto,diffcounto,x);
	}
	return x;

}

void print_arp_summary(struct ether_arp *arp_temppack, struct ether_header *eth_tempheader){

        if (ntohs (eth_tempheader->ether_type) == ETHERTYPE_ARP) {
		printf(" (MAC): %02x:%02x:%02x:%02x:%02x:%02x\t(IP): %d.%d.%d.%d\n",
			arp_temppack->arp_sha[0],
			arp_temppack->arp_sha[1],
			arp_temppack->arp_sha[2],
			arp_temppack->arp_sha[3],
			arp_temppack->arp_sha[4],
			arp_temppack->arp_sha[5],
			arp_temppack->arp_spa[0],
			arp_temppack->arp_spa[1],
			arp_temppack->arp_spa[2],
			arp_temppack->arp_spa[3]);
	}

}
void print_arp_basic(struct ether_arp *arp_temppack, struct ether_header *eth_tempheader){

	
	if (ntohs (eth_tempheader->ether_type) == ETHERTYPE_ARP) {
		if (toggle_arp_sniffer_d_yes == 1) {
			printf("Received new ARP Packet\nSender (MAC): %02x:%02x:%02x:%02x:%02x:%02x\t(IP): %d.%d.%d.%d\t",
				arp_temppack->arp_sha[0],
				arp_temppack->arp_sha[1],
				arp_temppack->arp_sha[2],
				arp_temppack->arp_sha[3],
				arp_temppack->arp_sha[4],
				arp_temppack->arp_sha[5],
				arp_temppack->arp_spa[0],
				arp_temppack->arp_spa[1],
				arp_temppack->arp_spa[2],
				arp_temppack->arp_spa[3]);
			printf("Target (MAC): %02x:%02x:%02x:%02x:%02x:%02x\t(IP): %d.%d.%d.%d\n",
				arp_temppack->arp_tha[0],
				arp_temppack->arp_tha[1],
				arp_temppack->arp_tha[2],
				arp_temppack->arp_tha[3],
				arp_temppack->arp_tha[4],
				arp_temppack->arp_tha[5],
				arp_temppack->arp_tpa[0],
				arp_temppack->arp_tpa[1],
				arp_temppack->arp_tpa[2],
				arp_temppack->arp_tpa[3]);
		} else if (toggle_arp_sniffer_n_yes == 1) {

                        printf("Received New ARP Packet\nSender (MAC): %02x:%02x:%02x:%02x:%02x:%02x\t(IP): %d.%d.%d.%d\t",
                                arp_temppack->arp_sha[0],
                                arp_temppack->arp_sha[1],
                                arp_temppack->arp_sha[2],
                                arp_temppack->arp_sha[3],
                                arp_temppack->arp_sha[4],
                                arp_temppack->arp_sha[5],
                                arp_temppack->arp_spa[0],
                                arp_temppack->arp_spa[1],
                                arp_temppack->arp_spa[2],
                                arp_temppack->arp_spa[3]);
                        printf("Target (MAC): %02x:%02x:%02x:%02x:%02x:%02x\t(IP): %d.%d.%d.%d\n",
                                arp_temppack->arp_tha[0],
                                arp_temppack->arp_tha[1],
                                arp_temppack->arp_tha[2],
                                arp_temppack->arp_tha[3],
                                arp_temppack->arp_tha[4],
                                arp_temppack->arp_tha[5],
                                arp_temppack->arp_tpa[0],
                                arp_temppack->arp_tpa[1],
                                arp_temppack->arp_tpa[2],
                                arp_temppack->arp_tpa[3]);


		}
	}

}

void print_arp_detail(struct ether_arp *arp_temppack, struct ether_header *eth_tempheader){

	int i;
	int host_address = 0;
	int tmb = 0;

	//Check to see if Broadcast
	for ( i = 0; i < 6; i++ ) {

		if (arp_temppack->arp_tha[i] == 0) {
			tmb++;
		}
	}

	if ( tmb == 6 ) {
		printf("Broadcast ");
	} else {
		printf("Unicast ");
	}

	//Interpret Opcode for request or reply
	int opcode;
	opcode = ntohs(arp_temppack->ea_hdr.ar_op);
	if (opcode == ARPOP_REQUEST) {
		printf("Request ~ ");
	}
	if (opcode == ARPOP_REPLY) {
		printf("Reply ~ ");
	}

	for ( i = 0; i < 4; i++ ) {

		if (arp_temppack->arp_spa[i] == arp_temppack->arp_tpa[i]) {
			host_address++; 
		}
	}

	if ( host_address == 4 ) {
		printf("Gratuitous ARP for %d.%d.%d.%d ",
				arp_temppack->arp_tpa[0],
				arp_temppack->arp_tpa[1],
				arp_temppack->arp_tpa[2],
				arp_temppack->arp_tpa[3]);
			if (opcode == ARPOP_REQUEST) {
				printf(" (Request)\n");
			}
			if (opcode == ARPOP_REPLY) {
				printf(" (Reply)\n");
			}
	} else {
		printf("ARP Packet from MAC Address %02x:%02x:%02x:%02x:%02x:%02x ~ ",
				arp_temppack->arp_sha[0],
				arp_temppack->arp_sha[1],
				arp_temppack->arp_sha[2],
				arp_temppack->arp_sha[3],
				arp_temppack->arp_sha[4],
				arp_temppack->arp_sha[5]);

		if (opcode == ARPOP_REQUEST) {
			printf("Who has %d.%d.%d.%d?  Tell %d.%d.%d.%d\n",
				arp_temppack->arp_tpa[0],
				arp_temppack->arp_tpa[1],
				arp_temppack->arp_tpa[2],
				arp_temppack->arp_tpa[3],
				arp_temppack->arp_spa[0],
				arp_temppack->arp_spa[1],
				arp_temppack->arp_spa[2],
				arp_temppack->arp_spa[3]);
		}
		
		if (opcode == ARPOP_REPLY) {
			printf("%d.%d.%d.%d is at %02x:%02x:%02x:%02x:%02x:%02x\n",
				arp_temppack->arp_spa[0],
				arp_temppack->arp_spa[1],
				arp_temppack->arp_spa[2],
				arp_temppack->arp_spa[3],
				arp_temppack->arp_sha[0],
				arp_temppack->arp_sha[1],
				arp_temppack->arp_sha[2],
				arp_temppack->arp_sha[3],
				arp_temppack->arp_sha[4],
				arp_temppack->arp_sha[5]);
		}

	}

}

int process_arp_packet (const struct pcap_pkthdr *header, const u_char *packet, int arg) {

	int retval;
	int packetlen = header->len;
	struct ether_header *eth_header;
	struct ether_arp *arp_packet;
	
	eth_header = (struct ether_header *) packet;
	arp_packet = (struct ether_arp *) (packet + ETH_HEADER_SIZE);

	if ((packet[12] == 8)&&(packet[13] == 6)) {
		retval = 1;
	} else {
		if (debug_yes) {
			printf("This is an 802.1q tagged packet ~ not an untagged ARP packet ~ ");
			printf("Packet length:  %d, Ether Type:  0x%02X%02X\n",packetlen,packet[12],packet[13]);
		}
		return 0;
	}

	// if true, process arp packet on new voip interface
	if (arg == 1) {

                // Don't do anything with processing or analyzing arp packets unless
                // this flag is set
                if (toggle_arp_sniffer_n_yes == 1) {

                        //printf("Processing ARP Packet on new voip interface\n");

                        //For newly received ARP Packet, copy Source MAC and Source IP Into new struct array
                        sourcecopy(arp_packet, &addressbuff_n[host_count_n]);

                        // packet count always increments for every new packet observed
                        packet_count_n++;

                        if (host_count_n == 0) {
                                host_count_n++;
                                if (debug_yes) {
                                        print_arp_basic(arp_packet, eth_header);
                                        printf("1st New host recorded via ARP Packet: \n");
                                        print_arp_detail(arp_packet, eth_header);
                                        printf("Recorded host count: %d\n\n",host_count_n);
                                        output_file(arp_packet, 1);
                                } else {
                                        fprintf(stdout,"New host #%d learned on %s:",host_count_n,vinterfaceTmp);
                                        print_arp_summary(arp_packet, eth_header);
                                        int arg = 1;
                                        output_file(arp_packet, arg);
                                }
                        } else {

                                compareval = packetcompare_n(arp_packet);

                                if (compareval == 0) {

                                        //New host observed
                                        host_count_n++;
                                        if (debug_yes) {
                                                print_arp_basic(arp_packet, eth_header);
                                                printf("New host recorded via:\n");
                                                print_arp_detail(arp_packet, eth_header);
                                                printf("Recorded host count: %d\n\n",host_count_n);
                                                output_file(arp_packet, 1);
                                        } else {
                                        	printf("New host #%d learned on %s:",host_count_n,vinterfaceTmp);
                                                print_arp_summary(arp_packet, eth_header);
                                                int arg = 1;
                                                output_file(arp_packet, arg);
                                        }
                                } else {
                                        //Not a new host
                                        if (debug_yes){
                                                print_arp_detail(arp_packet, eth_header);
                                                printf("Host already seen on %s  ~ recorded host count: %d ~  packet count:  %d\n\n",vinterfaceTmp,host_count_n,packet_count_n);

                                       }
                                }

			}

		}


	} else if (arg == 0) {

		// Don't do anything with processing or analyzing arp packets unless
		// this flag is set
		if (toggle_arp_sniffer_d_yes == 1) {
		
			//printf("Processing ARP Packet on default interface\n");

                	//For newly received ARP Packet, copy Source MAC and Source IP Into new struct array
                	//addressbuff_d[host_count_d] = sourcecopy(arp_packet);
                	sourcecopy(arp_packet, &addressbuff_d[host_count_d]);
			
			// packet count always increments for every new packet observed
                       	packet_count_d++;

	                if (host_count_d == 0) {
                        	host_count_d++;
                                if (debug_yes) {
                                        print_arp_basic(arp_packet, eth_header);
                                        printf("1st New host recorded via ARP Packet: \n");
                                        print_arp_detail(arp_packet, eth_header);
                                        printf("Recorded host count: %d\n\n",host_count_d);
                                        output_file(arp_packet, 0);
                                } else {
                                        printf("New host #%d learned on %s:",host_count_d,IfName_temp);
                                        print_arp_summary(arp_packet, eth_header);
                                        int arg = 0;
                                        output_file(arp_packet, arg);
                                }
			} else {
			
                        	compareval = packetcompare_d(arp_packet);

                        	if (compareval == 0) {
	
					//New host observed
                                	host_count_d++;
                                        if (debug_yes) {
                                                print_arp_basic(arp_packet, eth_header);
                                                printf("New host recorded via:\n");
                                                print_arp_detail(arp_packet, eth_header);
                                                printf("Recorded host count: %d\n\n",host_count_d);
                                                output_file(arp_packet, 0);
                                        } else {
                                        	printf("New host #%d learned on %s:",host_count_d,IfName_temp);
                                                print_arp_summary(arp_packet, eth_header);
                                                int arg = 0;
                                                output_file(arp_packet, arg);
                                        }
				} else {
					//Not a new host
                                	if (debug_yes){
                                        	print_arp_detail(arp_packet, eth_header);
                                        	printf("Host already seen on %s ~ recorded host count: %d ~  packet count:  %d\n\n",IfName_temp,host_count_d,packet_count_d);

 	                               }
				}

			}
		}

	}

	return retval;

}
