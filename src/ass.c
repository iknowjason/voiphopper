/*
    voiphopper - VoIP Hopper 
    Copyright (C) 2012 Jason Ostrom <jpo@pobox.com>

    This file is part of VoIP Hopper.

    VoIP Hopper is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    VoIP Hopper is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/
// VoIP Hopper ass.c ~ Assessment mode

#include <global_includes.h>
#include "asl.h"
#include "netinfo.h"
#include "mac.h"

// Functions
void toggle_arp_sniffer_d();
void toggle_arp_sniffer_n();
void start_ass_ui();
void verbose_toggle();

//From main.c
extern char *IfName_temp;
extern int debug_yes;

//From lldp.c
extern int spoof_lldp( char *IfName_temp );

//From voiphop.c
extern int spoof_cdp( char *IfName_temp );

//From asl.c
extern FILE *ofile;
extern FILE *ofile2;
extern FILE *myassfile1;
extern int process_arp_packet (const struct pcap_pkthdr *header, const u_char *packet, int arg);
extern struct macip addressbuff_n[65535];
extern int host_count_n;

// from main.c
extern void print_mac (char *s, mac_t *mac);

// variables
// By default, the ARP sniffer does not record packets on the default interface
int toggle_arp_sniffer_d_yes = 0;
// By default, the ARP sniffer does record packets on the new voip interface 
// This will be set to '1' once the new voip interface is created
int toggle_arp_sniffer_n_yes = 1;
// other variables
// Toggle CDP packet analysis, enabled by default, only on default interface
int toggle_cdp_analysis = 1;
int toggle_8021q_analysis = 1;
int toggle_lldp_analysis = 1;
int toggle_vlan_hop = 1;
int vlan_learned_8021q = 0;
char vinterface[BUFSIZ];
char *vinterfaceTmp;
int default_int = 0;
int new_int = 1;
int ass_cdp_vvid_dhcp = 0;
pthread_t myArpNewThread;
pthread_t mySnifferMainThread;
int newArpThreadCreated = 0;

#define MAX_LINE 100

struct vlan_header {
        u_char  other[2];
        u_short length;
};


void *sniff_arp_new(void *threadarg) {

	//printf("sniff_arp_new:  Add an arp sniffer on %s, len is %d\n",vinterface,strlen(vinterface));
	vinterfaceTmp = malloc(strlen(vinterface));
	strcpy(vinterfaceTmp,vinterface);

	//Get the thread ID of sniff_arp_new, and assign it to a global variable
	myArpNewThread = pthread_self();
	newArpThreadCreated = 1;

        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        char arp_filter_exp_new[] = "arp";
        const u_char *packet;
        struct pcap_pkthdr *header;

        // Open up the voip host logfile
        char *file_name2 = "voip-hosts.txt";
        ofile2 = fopen(file_name2, "w");

        if (ofile2 == NULL) {
                fprintf(stderr, "Error:  Unable to output the file %s\n",file_name2);
                exit (8);
        }

        if (vinterfaceTmp == NULL) {

                vinterfaceTmp = pcap_lookupdev(errbuf);

                if (vinterfaceTmp == NULL) {

                        fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
                        exit(EXIT_FAILURE);
                }
                printf("Interface not specified - Using first usable default device: ");
                printf("%s\n", vinterfaceTmp);
        }

        if (pcap_lookupnet(vinterfaceTmp, &net, &mask, errbuf) == -1) {

                fprintf(stderr, "Couldn't get netmask for device %s.  Enable the interface first and assign an IP address: %s\n", vinterfaceTmp, errbuf);
                net = 0;
                mask = 0;
                exit(EXIT_FAILURE);
        }
        printf("Capturing ARP packets on %s\n", vinterfaceTmp);

        handle = pcap_open_live(vinterfaceTmp, SNAP_LEN, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "pcap_open_live():  Couldn't open device %s: %s\n", vinterfaceTmp, errbuf);
                exit(EXIT_FAILURE);
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
                fprintf(stderr, "\n%s is not an Ethernet Interface\n", vinterfaceTmp);
                exit(EXIT_FAILURE);
        }

        if (pcap_compile(handle, &fp, arp_filter_exp_new, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter arp_filter_exp_new: %s: %s\n",
                arp_filter_exp_new, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                arp_filter_exp_new, pcap_geterr(handle));
                exit(EXIT_FAILURE);
        }

        for ( ; ; ){

                int pcap_return = pcap_next_ex(handle, &header, &packet);
		//printf("pcap_return value is:  %d\n",pcap_return);
                if(pcap_return <= 0) {

                } else {

			// passing 3rd argument of 1 means this libpcap is processing arp packet on new voip interface 
                        process_arp_packet(header,packet,new_int);
                }

        }

        pcap_freecode(&fp);
        pcap_close(handle);

}
void *sniffer_main(void *threadarg) {

	// Get the Sniffer Main Thread ID, and assign to the global variable
	mySnifferMainThread = pthread_self();

        // Open up the host logfile
        char *file_name = "hosts.txt";
        ofile = fopen(file_name, "w");

        if (ofile == NULL) {
                fprintf(stderr, "Error:  Unable to output the file %s\n",file_name);
                exit (8);
        }

	// Open up the assessment logfile
        char *file_name3 = "myass.txt";
        myassfile1 = fopen(file_name3, "w");

        if (myassfile1 == NULL) {
                fprintf(stderr, "Error:  Unable to output the file %s\n",file_name3);
                exit (8);
        }


        char errbuf_main[PCAP_ERRBUF_SIZE];
        pcap_t *handle_main;
        struct bpf_program fp_main;
        bpf_u_int32 mask_main;
        bpf_u_int32 net_main;
	/*
		ok, some filter expressions:
		CDP: "ether host 01:00:0c:cc:cc:cc and (ether[20:2] = 0x2000 or ether[24:2] = 0x2000)"
		ARP only on default interface:  "ether[12:2] = 0x0806 and (not vlan)"
		802.1Q:  "ether[12:2] = 0x8100"
		LLDP:  "ether host 01:80:c2:00:00:0e and (ether[16:2] = 0x88cc or ether[12:2] = 0x88cc)"

		This 'filter_exp_main' below is a combined filter expression to capture CDP, ARP on default int, 802.1Q, and LLDP'
	*/ 
        char filter_exp_main[] = "ether host 01:00:0c:cc:cc:cc and (ether[20:2] = 0x2000 or ether[24:2] = 0x2000) or (ether[12:2] = 0x0806 and ! vlan) or ether[12:2] = 0x8100 or (ether host 01:80:c2:00:00:0e and (ether[16:2] = 0x88cc or ether[12:2] = 0x88cc))";
        const u_char *packet_main;
        struct pcap_pkthdr *header_main;

        if (IfName_temp == NULL) {

                IfName_temp = pcap_lookupdev(errbuf_main);

                if (IfName_temp == NULL) {

                        fprintf(stderr, "Couldn't find default device: %s\n",errbuf_main);
                        exit(EXIT_FAILURE);
                }
                printf("Interface not specified - Using first usable default device: ");
                printf("%s\n", IfName_temp);
        }

        if (pcap_lookupnet(IfName_temp, &net_main, &mask_main, errbuf_main) == -1) {

                fprintf(stderr, "Couldn't get netmask for device %s.  Enable the interface first and assign an IP address: %s\n", IfName_temp, errbuf_main);
                net_main = 0;
                mask_main = 0;
                exit(EXIT_FAILURE);
        }

        printf("Main Sniffer:  capturing packets on %s\n", IfName_temp);

        handle_main = pcap_open_live(IfName_temp, SNAP_LEN, 1, 1000, errbuf_main);
        if (handle_main == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", IfName_temp, errbuf_main);
                exit(EXIT_FAILURE);
        }

        if (pcap_datalink(handle_main) != DLT_EN10MB) {
                fprintf(stderr, "\n%s is not an Ethernet Interface\n", IfName_temp);
                exit(EXIT_FAILURE);
        }

        if (pcap_compile(handle_main, &fp_main, filter_exp_main, 0, net_main) == -1) {
                fprintf(stderr, "Couldn't parse filter expression arp_filter_exp:   %s: error:  %s\n",
                filter_exp_main, pcap_geterr(handle_main));
                exit(EXIT_FAILURE);
        }

        if (pcap_setfilter(handle_main, &fp_main) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n",
                filter_exp_main, pcap_geterr(handle_main));
                exit(EXIT_FAILURE);
        }

        for ( ; ; ){

                int pcap_return = pcap_next_ex(handle_main, &header_main, &packet_main);
                if(pcap_return <= 0) {

                } else {
                        int retval = process_main_packet(header_main, packet_main);
                }

        }

        pcap_freecode(&fp_main);
        pcap_close(handle_main);

}

void start_ass_ui(){

	for ( ; ; ){

		char ch = 0;
		ch = getchar();
	
		switch(ch) {

			case 'a':
				toggle_arp_sniffer_d();
				// Toggle recording ARP packets on default interface ~ Default disabled 
				break;
			case 'b':
				toggle_arp_sniffer_n();
				// Toggle recording ARP packets on new VoIP VLAN interface ~ Default enabled 
				break;
			case 'c':
				//spoof 1 CDP packet ~ only on default interface
				spoof_cdp(IfName_temp);
				break;
			case 'd':
				// Toggle CDP sniffer ~ only on default interface ~ enabled by default
				if (toggle_cdp_analysis == 1) {
					fprintf(stdout,"Disabling analysis of CDP\n");
					toggle_cdp_analysis = 0;
				} else {
					fprintf(stdout,"Enabling analysis of CDP\n");
					toggle_cdp_analysis = 1;
				}
				break;
			case 'f':
				// Toggle 8021q sniffer ~ Enabled by default
				if (toggle_8021q_analysis == 1) {
                                        fprintf(stdout,"Disabling analysis of 802.1q\n");
                                        toggle_8021q_analysis = 0;
                                } else {
                                        fprintf(stdout,"Enabling analysis of 802.1q\n");
                                        toggle_8021q_analysis = 1;
                                }

				break;
			case 'h':
				text_help();
				break;
			case 'i':
				// Toggle Automatic VLAN Hop
				if (toggle_vlan_hop == 1) {
                                        fprintf(stdout,"Disabling automatic VLAN Hop\n");
                                        toggle_vlan_hop = 0;
				} else {
                                        fprintf(stdout,"Enabling automatic VLAN Hop\n");
                                        toggle_vlan_hop = 1;
				}
				break;
			case 'l':
				// Toggle LLDP-MED sniffer ~ enabled by default
                                if (toggle_lldp_analysis == 1) {
                                        fprintf(stdout,"Disabling analysis of LLDP-MED\n");
                                        toggle_lldp_analysis = 0;
                                } else {
                                        fprintf(stdout,"Enabling analysis of LLDP-MED\n");
                                        toggle_lldp_analysis = 1;
                                }

				break;
			case 'm':
				// Spoof 1 LLDP-MED packet 
				spoof_lldp(IfName_temp);
				break;
			case 'q':
				// Safely quit VoIP Hopper
				printf("Closing VoIP Hopper\n");
				return;
			case 's':
				// Spoof IP and MAC address
				printf("Spoof IP and MAC address ~ Become an IP Phone\n");
				spoof_ip_mac();
				break;
			case 'v':
				// Toggle debug mode on and off 
				verbose_toggle();
				break;
			case 'z':
				// About VoIP Hopper
				printf("VoIP Hopper %s\n",VERSION);
				printf("Copyright (C) 2011 Jason Ostrom  <jpo@pobox.com>\n");
				printf("Location:  http://voiphopper.sourceforge.net\n");
				break;
		}
		
	}
}
text_help(){

	printf("Please select from one of the following options:\n");
	printf("************************************************\n");
	printf("a   <------>   Toggle recording ARP packets on default interface ~ (Disabled by default)\n");
	printf("b   <------>   Toggle recording ARP packets on new VoIP VLAN interface ~ (Enabled by default)\n");
	printf("c   <------>   Spoof 1 CDP packet ~ Quickly discover VVID\n");
	printf("d   <------>   Toggle CDP packet analysis ~ (Enabled by default)\n");
	printf("f   <------>   Toggle 802.1q analysis ~ (Enabled by default)\n");
	printf("h   <------>   Print help menu\n");
	printf("i   <------>   Toggle automatic VLAN Hop ~ (Enabled by default)\n");
	printf("l   <------>   Toggle analysis of LLDP-MED ~ (Enabled by default)\n");
	printf("m   <------>   Spoof 1 LLDP-MED packet ~ Quickly learn VVID\n");
	printf("q   <------>   Safely quit VoIP Hopper\n");
	printf("s   <------>   Spoof my IP and MAC address\n");
	printf("v   <------>   Toggle verbose mode on and off\n");
	printf("z   <------>   About VoIP Hopper\n");
	printf("************************************************\n\n");

}
void toggle_arp_sniffer_d(){

	if (toggle_arp_sniffer_d_yes == 0) {
		printf("Analyzing ARP packets on default interface: %s\n",IfName_temp);
		toggle_arp_sniffer_d_yes = 1;

	} else if (toggle_arp_sniffer_d_yes == 1) {
		printf("Disabling analysis of ARP packets on default interface:  %s\n",IfName_temp);
		toggle_arp_sniffer_d_yes = 0;

	}
}
void toggle_arp_sniffer_n(){

        if (toggle_arp_sniffer_n_yes == 0) {
                printf("Analyzing ARP packets on new VoIP VLAN interface\n");
                toggle_arp_sniffer_n_yes = 1;

        } else if (toggle_arp_sniffer_n_yes == 1) {
                printf("Disabling analysis of ARP packets on new VoIP VLAN interface\n");
                toggle_arp_sniffer_n_yes = 0;

        }

}
void verbose_toggle(){

	if(debug_yes == 0){
		debug_yes = 1;
		printf("Verbose mode enabled\n");
	} 
	
	else if (debug_yes == 1) {
		debug_yes = 0;
		printf("Verbose mode disabled\n");
	}

}
int get_8021q(const struct pcap_pkthdr *header, const u_char *packet) {

        int packetlen = header->len;
        const struct ethernet_header *eth_ptr;
        const struct vlan_header *vlan;

	eth_ptr = (struct ethernet_header*)(packet);
	vlan = (struct vlan_header*)(packet + SIZE_ETHERNET);

	if(debug_yes) {
		fprintf(stdout,"Received 802.1q packet of %d bytes\n",packetlen);
	}

	int mynum = 0;

	int c1 = 0x01;
	int c2 = 0x02;
	int c3 = 0x04;
	int c4 = 0x08;
	int c5 = 0x10; //16
	int c6 = 0x20; //32
	int c7 = 0x40; //64
	int c8 = 0x80; //128
		
	int testbit0 = vlan->other[1] & c1;
	if (testbit0 == 1) {
		mynum = mynum + 1;
	}

	int testbit1 = vlan->other[1] & c2;
	if (testbit1 == 2) {
		mynum = mynum + 2;
	}

	int testbit2 = vlan->other[1] & c3;
	if (testbit2 == 4) {
		mynum = mynum + 4;
	}

	int testbit3 = vlan->other[1] & c4;
	if (testbit3 == 8) {
		mynum = mynum + 8;
	}

	int testbit4 = vlan->other[1] & c5;
	if (testbit4 == 16) {
		mynum = mynum + 16;
	}
	
	int testbit5 = vlan->other[1] & c6;
	if (testbit5 == 32) {
		mynum = mynum +32;
	}

	int testbit6 = vlan->other[1] & c7;
	if (testbit6 == 64) {
		mynum = mynum + 64;
	}

	int testbit7 = vlan->other[1] & c8;
	if (testbit7 == 128) {
		mynum = mynum +128;
	}

	int testbit8 = vlan->other[0] & c1;
	if (testbit8 == 1) {
		mynum = mynum + 256;
	}

	int testbit9 = vlan->other[0] & c2;
	if (testbit9 == 2) {
		mynum = mynum + 512;
	} 

	int testbit10 = vlan->other[0] & c3;
	if (testbit10 == 4) {
		mynum = mynum + 1024;
	}

	int testbit11 = vlan->other[0] & c4;
	if (testbit11 == 8) {
		mynum = mynum + 2048;
	}

	// Check to see if vlan already is learned through 8021.q
	if(vlan_learned_8021q == 0) {
		fprintf(stdout,"Decoded VLAN ID through 802.1q VLAN Header:  %d\n",mynum);
		vlan_learned_8021q = 1;
		return mynum;
	}

}
int process_main_packet( const struct pcap_pkthdr *header, const u_char *packet) {

        int packetlen = header->len;
	int something = 0;

	// check to see if CDP packet
	if ((check_if_cdp(header, packet) == 1) && (toggle_cdp_analysis == 1)) {

		//fprintf(stdout,"Received CDP packet of %d bytes\n",packetlen);
		something = 1;

		u_char *args;
		int vvid_cdp = 0;
		vvid_cdp = get_cdp(args, header, packet);
		if ((vvid_cdp != 0)&&(ass_cdp_vvid_dhcp == 0)) {
			
			if (toggle_vlan_hop == 1) {
				vlan_hop_cdplldp(vvid_cdp);
			}

		}

	} else {

	}
	// check to see if ARP packet
	if (check_if_arp(header, packet) == 1) {
		//fprintf(stdout,"Received ARP packet on default interface of %d bytes\n",packetlen);
		something = 1;
		int retval = process_arp_packet(header, packet, default_int);
	} else {
		
	}
	// check to see if 802.1Q
	if ((check_if_8021Q(header, packet) == 1) && (toggle_8021q_analysis == 1)) {
		//fprintf(stdout,"Received 802.1q packet of %d bytes\n",packetlen);
		something = 1;

		int tagvlanid;
		tagvlanid = get_8021q(header, packet);

		/* If new VVID is discovered in 802.1q packet and this hasn't been done before, then VLAN Hop */
		if((tagvlanid != 0)&&(ass_cdp_vvid_dhcp == 0)) {

			// Need to VLAN Hop and DHCP
			if (toggle_vlan_hop == 1) {
				vlan_hop_cdplldp(tagvlanid);
			}

		}
	} else {


	}
	// check to see if LLDP-MED
	if ((check_if_lldp(header, packet) == 1) && (toggle_lldp_analysis == 1)) {
		//fprintf(stdout,"Received LLDP-MED packet of %d bytes\n",packetlen);
		something = 1;
		int vvid_lldp = 0;
		vvid_lldp = get_lldp(header, packet);
		/* If new VVID is discovered in LLDP packet and this hasn't been done before, then VLAN Hop*/
		if ((vvid_lldp != 0)&&(ass_cdp_vvid_dhcp == 0)) {

			if (toggle_vlan_hop == 1) {
				vlan_hop_cdplldp(vvid_lldp);
			}
		}

	} else {

	}

	if ( something == 0) {
		// check to see if we are analyzing CDP ~ if not, we shouldn't say can't decode packet, because it could have been a CDP packet
		printf("Something is 0:  Test, toggle_cdp_analysis:  %d\n",toggle_cdp_analysis);
		if (toggle_cdp_analysis == 1) {
			fprintf(stderr,"Can't decode packet, other type of %d bytes\n",packetlen);
			return something;
		}
	}
	return something;

}
int check_if_arp(const struct pcap_pkthdr *header, const u_char *packet) {

	// check to make sure ARP only on default interface:  "ether[12:2] = 0x0806 and ! vlan"
        int retval_arp_true = 0;
        int packetlen = header->len;

	if((packet[12] == 0x81) && (packet[13] == 0x00)) {

		//printf("An 802.1Q packet, but supposed to be a non VLAN 802.1q\n");
		return retval_arp_true;

	} else {
		if((packet[12] == 0x08) && (packet[13] == 0x06)) {
			//printf ("Received ARP packet of %d bytes\n",packetlen);
			retval_arp_true = 1;
			return retval_arp_true;
		} else {
			//printf("Not an ARP packet\n");
			return retval_arp_true;

		}
	}


}
int check_if_8021Q(const struct pcap_pkthdr *header, const u_char *packet) {

        int retval_8021q_true = 0;
        int packetlen = header->len;
	if((packet[12] == 0x81) && (packet[13] == 0x00)) {
		retval_8021q_true = 1;
		//printf ("Received 802.1q packet of %d bytes\n",packetlen);
		return retval_8021q_true;
	} else {
		return retval_8021q_true;
	}
}
int check_if_lldp(const struct pcap_pkthdr *header, const u_char *packet) {

	//LLDP:  "ether host 01:80:c2:00:00:0e and (ether[16:2] = 0x88cc or ether[12:2] = 0x88cc)"
        int retval_lldp_true = 0;
        int packetlen = header->len;

	if ((packet[0] == 0x01 )&&(packet[1] == 0x80)&&(packet[2] == 0xC2)&&(packet[3] == 0x00)&&(packet[4] == 0x00)&&(packet[5] == 0x0E)) {

		//fprintf(stdout,"packet is correct lldp multicast destination\n");

		if((packet[16] == 0x88)&&(packet[17] == 0xCC)){

			//fprintf(stdout,"lldp packet, 802.1q\n");
			retval_lldp_true = 1;
			return retval_lldp_true;

		} else if ((packet[12] == 0x88)&&(packet[13] == 0xCC)) {

			//fprintf(stdout,"lldp packet, IEEE 802.3\n");
			retval_lldp_true = 1;
			return retval_lldp_true;
		} else {
			//fprintf(stdout,"Something wrong decoding potential lldp packet\n");
			return retval_lldp_true;
		}


	} else {
		return retval_lldp_true;

	}


}
int vlan_hop_cdplldp (int vvid_learned) {

        bpf_u_int32 mask_cdp;
        bpf_u_int32 net_cdp;
	char errbuf_cdp[PCAP_ERRBUF_SIZE];

        /* create string for new voice interface */
        snprintf(vinterface, sizeof(vinterface), "%s.%d", IfName_temp, vvid_learned);

        /* Check to make sure interface isn't already configured */
        int retval = pcap_lookupnet(vinterface, &net_cdp, &mask_cdp, errbuf_cdp);
        if (retval == 0) {

                // vinterface already exists
                /* Get network address and netmask */
                char *net_str = NULL;
                char *mask_str = NULL;
                struct in_addr tmp_ip;
                struct in_addr tmp_mask;
                memcpy(&tmp_ip.s_addr, &net_cdp, sizeof(u_int8_t)*4);
                net_str = inet_ntoa(tmp_ip);

                printf("Voice VLAN interface %s is already configured\n\n",vinterface);

                if(net_str == NULL) {
                        perror("inet_ntoa error\n");
                        return(-1);
                } else {
                        if(debug_yes) {
                                printf("Network Address:  %s\n", net_str);
                        }
                }

                memcpy(&tmp_mask.s_addr, &mask_cdp, sizeof(u_int8_t)*4);
                mask_str = inet_ntoa(tmp_mask);

                if(mask_str == NULL) {
                        perror("inet_ntoa error\n");
                        return(-1);
                } else {
                        if(debug_yes) {
                                printf("Netmask:  %s\n",mask_str);
                        }
                }

               if(debug_yes) {
                        printf("\nTo delete interface, run command:\n");
                        printf("'voiphopper -d %s'\n\n",vinterface);
                }
        } else {

                /* Add the VVID interface */
                create_vlan_interface(IfName_temp,vvid_learned);
                if(debug_yes) {
                        printf("Added VLAN %u to Interface %s\n",vvid_learned, IfName_temp);
                        printf("Attempting dhcp request for new interface %s\n",vinterface);
                }
		
                // DHCP client call after I've learned the VVID through CDP or LLDP 
                int return_value = dhcpclientcall(vinterface);

		// If dhcp has timed out, or another dhcp error
		if (return_value == -1) {

			// Set the IP address to a non RFC 1918 address, which would have an extremely low probability of an IP conflict on an internal IP network
			char *randomIP = "9.9.9.9";
			SetIP(vinterface, randomIP);
			int retval = ifup(vinterface);
		}

                // Set the recording of ARP packets on for new VoIP interface
                toggle_arp_sniffer_n_yes = 1;

                // Now start ARP Sniffer on new VoIP interface
                // Create new thread
                pthread_t new_arp_threads;
                int rc;
                int arg;
                rc = pthread_create(&new_arp_threads,NULL,sniff_arp_new,(void *)arg);
                if(rc) {
                        printf("Error:  pthread_create error %d\n",rc);
                        exit(-1);
                }

		// make sure this function doesn't run again
		ass_cdp_vvid_dhcp = 1;

        }

}
spoof_ip_mac() {

	cancelthreads();

	int phoneindex = displaymenu(host_count_n);

	//char *Interface = "eth0";

	//int spoof = spoofIPPhone(phoneindex, Interface);
	int spoof = spoofIPPhone(phoneindex, vinterfaceTmp);

}
cancelthreads(){

	int retval;

        if(newArpThreadCreated == 1) {
                //Cancel the thread IDs of sniff_main and sniff_arp_new
                retval = pthread_cancel(myArpNewThread);
                if(retval != 0) {
                        printf("Error cancelling thread ID for sniff_arp_new\n");

                } else {
                        //able to cancel the thread
                }
        }


        retval = pthread_cancel(mySnifferMainThread);
        if(retval != 0) {
                printf("Error cancelling thread ID for sniffer_main\n");

        } else {
                //able to cancel the thread
        }
}
int displayIPs(struct macip *mymacip){

	int a;
	int count = 1;
	for (a = 0; a < host_count_n; a++) {
		//print index
		printf("(%d)	",count);

		// print IP address
		printf("IP:   %d.%d.%d.%d, ",
			mymacip[a].ip[0], 
			mymacip[a].ip[1], 
			mymacip[a].ip[2],
			mymacip[a].ip[3]);

		// print MAC address
		printf("	MAC:   %02x:%02x:%02x:%02x:%02x:%02x\n",
			mymacip[a].mac[0],
			mymacip[a].mac[1],
			mymacip[a].mac[2],
			mymacip[a].mac[3],
			mymacip[a].mac[4],
			mymacip[a].mac[5]);

		count++;
	}
}
int displaymenu(int host_count){

	if (host_count == 0) {
		printf("You must discover at least 1 other phone in order to spoof a potential IP phone\n");
		return 0;
	}

	getchar();
	int repeat = 1;
	int myreturn;

        do {
	
		int display = displayIPs(addressbuff_n);

		char line[MAX_LINE];
		char *result;

		printf("\nSelect an IP Phone index (1 - %d) to spoof the MAC and IP Address of, 'q' to Quit, or 'r' to repeat Phone list\n", host_count_n);
		if((result = gets(line)) != NULL){
		//if((result = fgets(line, 10, STDIN)) != NULL){

			if (checkinput_alpha(line) == 0) {

				int retv = checkinput_numeric(line);
				if (retv != 0) {
					//printf("IP Phone index of %d selected!\n",retv);
					repeat = 0;
					myreturn = retv;

				}
				

			} else {

				//interpret that 1 alpha character

				if(line[0] == 'q') {
					printf("VoIP Hopper exiting\n");
					exit(1);
				} else if (line[0] == 'r'){

					printf("Repeat IP Phone display list:\n\n");
					// Do nothing - we are going to repeat
				} else {
					printf("Unrecognized character (%c) ~ only supported options are 'r' to repeat IP Phone list, or 'q' to quit.\n",line[0]);
				}

			}

		} else if (ferror(stdin)) {
			perror("Error");
		}

	} while (repeat == 1);

	return myreturn;

}
int checkinput_numeric(char *str) {

	int len = strlen(str);
	// non-zero is the correct index of phone in numeric format 
	// 0 returns error

	// check if all characters in string are numeric
	int a;
	int numeric_count = 0;
	for (a = 0; a < len; a++) {

		// loop through and check the characters
                int y = isdigit(str[a]);
                if(y == 0) {
                        //printf("%c is not numeric!\n",str[a]);

                } else {

                        //printf("%c is numeric!\n",str[a]);
			numeric_count++;
                }

	}
	
	if(numeric_count == len) {

		//printf("All numeric characters!\n");

		// convert from str to integer
		int count = atoi(str);

		// make sure it is in range
		if( count <= host_count_n) {

			//printf("Count is good within range ~ %d!\n",count);
			return count;

		} else {

			printf("\nYou've specified an IP Phone index (%d) that is out of range.  Please select range:  1 - %d.\n\n",count,host_count_n);
			return 0;
		}

	} else {

		printf("\nYou entered an invalid string of '%s' ~ Please select numeric index of IP Phone range, 'q', or 'r'.\n\n",str); 
		// Not all numeric characters
		return 0;

	} 
	
}
int checkinput_alpha(char *str) {


        int len = strlen(str);

	// if return 0, can't be only one alpha character
	// Return 1 if 1 alpha character

        //printf("Inside of checkinput_alpha():  String is %s, len:  %d\n",str,len);

        if(len == 1) {

                if(isalpha(str[0]) != 0) {

                        //User selected 1 alpha character!

                        return 1;
                } else {
			return 0;

		}
        } else {

		return 0;

	}

}
int spoofIPPhone(int index, char *interface){

	index = index - 1;

	//unsigned char mac_bytes[6] = { 0x00, 0x0B, 0xe4, 0x7e, 0x98, 0x63 };

	// Get IP address we need to become, from IP Phone index
	/*printf("addressbuff_n mac:  %02x %02x %02x %02x %02x %02x\n",
		addressbuff_n[index].mac[0],
		addressbuff_n[index].mac[1],
		addressbuff_n[index].mac[2],
		addressbuff_n[index].mac[3],
		addressbuff_n[index].mac[4],
		addressbuff_n[index].mac[5]);

	printf("addressbuff_n ip:  %d.%d.%d.%d\n",
		addressbuff_n[index].ip[0],
		addressbuff_n[index].ip[1],
		addressbuff_n[index].ip[2],
		addressbuff_n[index].ip[3]);*/

	char newstr[15];
	snprintf(newstr, sizeof(newstr), "%d.%d.%d.%d",
		addressbuff_n[index].ip[0],
		addressbuff_n[index].ip[1],
		addressbuff_n[index].ip[2],
		addressbuff_n[index].ip[3]);

	//printf("Setting IP address to:  %s\n",newstr);

	SetIP(interface, newstr);
	SetMAC(interface, addressbuff_n[index].mac);

	int retval = ifup(interface);

}
int SetIP(const char* interface, const char * address)
{
	int test_sock = 0;
	struct sockaddr_in* addr = NULL;
	struct ifreq ifr;

	memset( &ifr, 0, sizeof( struct ifreq ) );
	addr = (struct sockaddr_in *)&(ifr.ifr_addr);
	memset(addr, 0, sizeof( struct sockaddr_in) );
	//addr->sin_len=sizeof(struct sockaddr_in);
	addr->sin_family=AF_INET;
	addr->sin_addr.s_addr=inet_addr(address);

	test_sock = socket( PF_INET, SOCK_DGRAM, 0 );
	if( test_sock == -1 ) {
		printf("Cannot obtain socket :%s\n",strerror(errno));
		return (-1);
	}

	strncpy( ifr.ifr_name,interface,IFNAMSIZ);
	if( ioctl( test_sock, SIOCSIFADDR, &ifr ) != 0 ) {
		printf("Cannot set IP address of interface '%s' to '%s':  %s\n",interface,address,strerror(errno)); 
		close(test_sock);
		return (-1);
	} else {
		printf("IP address of '%s' set to '%s'\n",interface,address);
		close(test_sock);
		return(0);
	}
}
int SetMAC(char *interface, unsigned char *bytes) {

	unsigned char *mac_to_spoof;
	mac_to_spoof = mc_macbytes_into_string(bytes);

	//interface = "eth0";

        net_info_t      *neti;
        mac_t   *mac;
        mac_t   *mac_faked;

	/* Read the MAC */
	if ((neti = mc_net_info_new(interface)) == NULL) exit(1);
	mac = mc_net_info_get_mac(neti);

	/* Print the current MAC info */
	print_mac ("Current MAC: ", mac);

	/* Change the MAC */
	mac_faked = mc_mac_dup (mac);

	if (mc_mac_read_string (mac_faked, mac_to_spoof) < 0) {
		printf("Something Wrong spoofing MAC!!\n");
		exit(1);
	} else {
		//Success!!
	}

	/* Set the new MAC */
	if (mc_net_info_set_mac (neti, mac_faked) >= 0) {
		/* Re-read the MAC */
		mc_mac_free (mac_faked);
		mac_faked = mc_net_info_get_mac(neti);

		/* Print it */
		print_mac ("Faked MAC:   ", mac_faked);

		/* Is the same MAC? */
		if (mc_mac_equal (mac, mac_faked)) {
			printf ("It's the same MAC Address.\n");
		}

	}

	/* Memory free */
	mc_mac_free (mac);
	mc_mac_free (mac_faked);
	mc_net_info_free (neti);

}
