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
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <linux/if_vlan.h>
#include <net/if.h>
#include <linux/sockios.h>

#include "pathnames.h"
#include "dhcpclient.h"
#include "signals.h"
#include "mac.h"
#include "maclist.h"
#include "netinfo.h"
#include "protocols.h"
#include "packets.h"
#include "voiphop.h"
#include "pthread.h"
#include "global_includes.h"

#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define SIZE_LLC 8

#define SIZE_VLAN 4

#define SIZE_CDPHEADER 4

#define IP_ALEN         IP_ADDR_LEN
#define DEFAULT_NUMBER  100;
#define DEFAULT_LENGTH  1400;

struct in_addr  inform_ipaddr,default_router;
int avaya_vvid_disc;
int nortel_vvid_disc;
int alcatel_vvid_disc;
int alcatelmode = 0;
extern char *ProgramName;
extern char **ProgramEnviron;
extern char *IfName;
extern char *lldpDeviceID;
char *IfName_temp;
extern char *IfNameExt;
extern char *RemIfName;
extern int IfName_len;
extern int IfNameExt_len;
extern char *HostName;
extern int HostName_len;
extern char *Cfilename;
extern unsigned char *ClassID;
extern int ClassID_len;
extern unsigned char   *ClientID;
extern int             ClientID_len;
void            *(*currState)() =       &dhcpReboot;
extern int             DebugFlag;
extern int             BeRFC1541;
extern unsigned        LeaseTime;
extern int             ReplResolvConf;
extern int             ReplNISConf;
extern int             ReplNTPConf;
extern int             SetDomainName;
extern int             SetHostName;
extern int             BroadcastResp;
extern time_t          TimeOut;
extern int             magic_cookie;
extern unsigned short  dhcpMsgSize;
extern unsigned        nleaseTime;
extern int             DoCheckSum;
extern int             TestCase;
extern int             SendSecondDiscover;
extern int             Window;
extern char            *ConfigDir;
extern int             SetDHCPDefaultRoutes;
extern int 		avvid;
extern int 		nvvid;
extern int 		tvvid;
extern int 		*avvid2;
extern int 		*nvvid2;
extern int 		*tvvid2;
extern char 		apattern[];
char 		vinterface[BUFSIZ];
int debug_yes = 0;
int macy = 0;
char *set_mac     = NULL;
// From asl.c

// from ass.c
extern void *sniffer_main(void *threadarg);

extern u_char CDP_DEST;
#define CDP_FRAME_SIZE 1700
u_char cdpframe[CDP_FRAME_SIZE];

#if 0
unsigned char   ClientMACaddr[ETH_ALEN];
int             ClientMACaddr_ind =     0;
#endif


void print_app_banner(void);

extern unsigned int mk_spoof_cdp(char *S_deviceidC,char *S_portidC,char *S_softwareC,char *S_platformC,char *S_capasC,char *S_duplexC);

void print_version();

void print_app_usage(void);

void print_app_base_usage(void);

void print_help_usage(void);

void print_app_vlan_usage(void);

void print_avaya_usage(void);

void print_alcateliptouch_usage(void);

void print_nortel_usage(void);

void print_mac_usage(void);

void print_app_banner(void)
{
return;
}

void print_mac (char *s, mac_t *mac)
{
        char string[18];
        mc_mac_into_string (mac, string);
        printf ("%s %s %s \n", IfName, s, string);
}

void print_mac_new_interface (char *s, mac_t *mac)
{
        char string[18];
        mc_mac_into_string (mac, string);
        printf ("%s %s %s \n", vinterface, s, string);
}


void
print_app_usage(void)
{

	printf("Usage: %s [-i interface] [-l] [-m MAC] [-a] [-n] [-t 0|1] [-v VLANID] [-D]\n", APP_NAME);
	printf("\n");
	printf("Options:\n");
	printf("    -i    Interface to sniff on\n");
	printf("    -l    List available interfaces\n");
	printf("    -m    MAC Address to spoof\n");
	printf("    -a    Avaya DHCP client spoofing of Option 176 and 242\n");
	printf("    -n    Nortel DHCP client spoofing of Option 191\n");
	printf("    -t    Alcatel VLAN discovery\n");
	printf("    -v    Vlan to hop to without sniffing\n");
	printf("    -D    Don't change the  MAC address of default interface\n");
	printf("\n");

return;
}


void print_app_base_usage(void){

        printf("%s -i <interface> -c {0|1|2} -l <DEVICEID> -a -n -v <VLANID>\n\n", APP_NAME);
	printf("Please specify 1 base option mode:\n\n");
	printf("LLDP Spoof Mode (-o 001EF7289C8E)\n");
	printf("Example:  voiphopper -i eth0 -o 001EF7289C8E\n\n");

	printf("CDP Sniff Mode (-c 0)\n");
	printf("Example:  voiphopper -i eth0 -c 0\n\n");
	printf("CDP Spoof Mode with custom packet (-c 1):\n");
	printf("-E <string> (Device ID)\n");
	printf("-P <string> (Port ID)\n");
	printf("-C <string> (Capabilities)\n");
	printf("-L <string> (Platform)\n");
	printf("-S <string> (Software)\n");
	printf("-U <string> (Duplex)\n");
	printf("Example:  voiphopper -i eth0 -c 1 -E 'SIP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P003-08-8-00' -U 1\n\n");
	printf("CDP Spoof Mode with pre-made packet (-c 2)\n");
	printf("Example:  voiphopper -i eth0 -c 2\n\n");
	printf("Avaya DHCP Option Mode (-a):\n");
	printf("Example:  voiphopper -i eth0 -a\n\n");
	printf("VLAN Hop Mode (-v VLAN ID):\n");
	printf("Example:  voiphopper -i eth0 -v 200\n\n");
	printf("Nortel DHCP Option Mode (-n):\n");
	printf("Example:  voiphopper -i eth0 -n\n\n");
	printf("Alcatel Mode (-t 0|1):\n");
	printf("Example:  voiphopper -i eth0 -t 0\n\n");
	printf("'voiphopper -h' for more help\n");

}

void print_help_usage(void){

	printf("VoIP Hopper Extended Usage:\n\nMiscellaneous Options:\n");
	printf("	-l (list available interfaces for CDP sniffing, then exit)\n");
	printf("	Example:  voiphopper -l\n");
	printf("	-m (Spoof the MAC Address, then exit)\n");
	printf("	Example:  voiphopper -i eth0 -m 00:07:0E:EA:50:86\n");
	printf("	-d (Delete the VLAN Interface, then exit)\n");
	printf("	Example:  voiphopper -d eth0.200\n");
	printf("	-V (Print the VoIP Hopper version, then exit)\n");
	printf("	Example:  voiphopper -V\n\n");
	printf("MAC Address Spoofing Options (used with -a, -v, or -c options):\n");
	printf("	-m (Spoof the MAC Address of existing interface, and new Interface)\n");
	printf("	-D -m (Spoof the MAC Address of only new Voice Interface)\n");
	printf("	Example:  voiphopper -i eth0 -m 00:07:0E:EA:50:86\n");
	printf("	Example:  voiphopper -i eth0 -D -m 00:07:0E:EA:50:86\n\n");
	printf("CDP Sniff Mode (-c 0)\n");
        printf("	Example:  voiphopper -i eth0 -c 0\n\n");
	printf("CDP Spoof Mode (-c 1):\n");
        printf("	-E <string> (Device ID)\n");
        printf("	-P <string> (Port ID)\n");
        printf("	-C <string> (Capabilities)\n");
        printf("	-L <string> (Platform)\n");
        printf("	-S <string> (Software)\n");
        printf("	-U <string> (Duplex)\n");
        printf("\nExample Usage for SIP Firmware Phone:\nvoiphopper -i eth0 -c 1 -E 'SIP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P003-08-8-00' -U 1\n");
        printf("\nExample Usage for SCCP Firmware Phone:\nvoiphopper -i eth0 -c 1 -E 'SEP0070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P00308000700' -U 1\n");
        printf("\nExample Usage for Phone with MAC Spoofing:\nvoiphopper -i eth0 -m 00:07:0E:EA:50:86 -c 1 -E 'SEP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P003-08-8-00' -U 1\n\n");
	printf("Avaya DHCP Option Mode (-a):\n");
	printf("	Example:  voiphopper -i eth0 -a\n");
	printf("	Example:  voiphopper -i eth0 -a -m 00:07:0E:EA:50:86\n\n");
        printf("VLAN Hop Mode (-v VLAN ID):\n");
        printf("	Example:  voiphopper -i eth0 -v 200\n");
	printf("	Example:  voiphopper -i eth0 -v 200 -D -m 00:07:0E:EA:50:86\n");
        printf("\nAlcatel VLAN Discovery (-t 0|1|2):\n");
	printf("	Example:  voiphopper -i eth0 -t 0\n");
	printf("	Example:  voiphopper -i eth0 -t 1\n");
	printf("	Example:  voiphopper -i eth0 -t 0 -m 00:80:9f:ad:42:42\n");
	printf("	Example:  voiphopper -i eth0 -t 1 -m 00:80:9f:ad:42:42\n");
	printf("	Example:  voiphopper -i eth0 -t 2 -v 800\n");
	printf("	Example:  voiphopper -i eth0 -t 2 -v 800 -m 00:80:9f:ad:42:42\n\n");


}

void print_version()
{
	printf("VoIP Hopper %s\nCopyright (C) 2012 Jason Ostrom ",VERSION);
	printf(" <jpo@pobox.com>\nLocation:  http://voiphopper.sourceforge.net\n");  
}


void print_app_vlan_usage(void){

	printf("Usage requires Interface and VLAN ID\n");
	printf("Usage: %s [-i interface] [-v VLANID]\n", APP_NAME);
	printf("Example: %s -i eth1 -v 201\n", APP_NAME); 

return;
}

void print_avaya_usage(void) {
        printf("Usage requires Interface and Avaya flag\n");
        printf("Usage: %s [-i interface] [-a]\n", APP_NAME);
        printf("Example: %s -i eth1 -a\n", APP_NAME);

return;
}

void print_alcateliptouch_usage(void) {
        printf("Usage requires Interface and Alcatel flag\n");
        printf("Usage: %s [-i interface] [-t 0|1|2]\n", APP_NAME);
        printf("        Example:  voiphopper -i eth0 -t 0\n");
        printf("        Example:  voiphopper -i eth0 -t 1\n");
        printf("        Example:  voiphopper -i eth0 -t 0 -m 00:80:9f:ad:42:42\n");
        printf("        Example:  voiphopper -i eth0 -t 1 -m 00:80:9f:ad:42:42\n");
        printf("        Example:  voiphopper -i eth0 -t 2 -v 800\n");
        printf("        Example:  voiphopper -i eth0 -t 2 -v 800 -m 00:80:9f:ad:42:42\n");

	return;
}


void print_nortel_usage(void) {

        printf("Usage requires Interface and Nortel flag\n");
        printf("Usage: %s [-i interface] [-n]\n", APP_NAME);
        printf("Example: %s -i eth1 -n\n", APP_NAME);

}

void print_mac_usage(void)
{
        printf("Usage requires Interface and MAC Address\n");
        printf("Usage: %s [-i interface] [-m MAC]\n", APP_NAME);
        printf("Example: %s -i eth1 -m 00:12:3F:0F:33:F3\n", APP_NAME);

return;
}

void remove_interface(char *RemovedInterface){

	printf("VoIP Hopper %s removing interface %s\n",VERSION,RemovedInterface);

	struct vlan_ioctl_args if_request;
	int fd;
	int vvid;

	strcpy(if_request.device1, RemovedInterface);

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		fprintf(stderr, "Fatal:  Couldn't open socket\n");
			exit(2);
	}	

	if_request.cmd = DEL_VLAN_CMD;
	if (ioctl(fd, SIOCSIFVLAN, &if_request) < 0) {
		fprintf(stderr, "Error trying to remove VLAN Interface %s.  Error: %s\n", RemovedInterface, strerror(errno));
	} else {
		fprintf(stdout, "Removed VLAN Interface %s\n", RemovedInterface);
	} 

}

void checkIfAlreadyRunning() {
	int o;
	char pidfile[64];
	snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,ConfigDir,IfName);
	o=open(pidfile,O_RDONLY);
	if ( o == -1 ){
		return;
	}
	close(o);
	fprintf(stderr,"\
	%s dhcp client: already running\n\
	%s dhcp client: if not then delete %s file\n",ProgramName,ProgramName,pidfile);
	exit(1);
}


int main(int argc, char *argv[])
{

	int k = 1;
	int i = 1;
	int j;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle;
	char o;

	/* dhcp stuff */
        int killFlag = 0;
        int versionFlag = 0;
        int s = 1;

        char cdp_filter_exp[] = "ether host 01:00:0c:cc:cc:cc and (ether[20:2] = 0x2000 or ether[24:2] = 0x2000)";
        struct bpf_program fp;
        bpf_u_int32 mask;
        bpf_u_int32 net;
        int num_packets = 100;
        const u_char *packet;
        struct pcap_pkthdr *header;
        print_app_banner();
	pcap_if_t *alldevsp;
	char *vlan_hop = NULL;
	int vvid;
	int intsp = 0;
	int dont_set = 0;
	int vhop_yes = 0;
	int lldpspoof_yes = 0;

	/* for gnu mac changer */
        char random       = 0;
        char endding      = 0;
        char another_any  = 0;
        char another_same = 0;
        char print_list   = 0;
        char show         = 0;
        char *search_word = NULL;

        struct option long_options[] = {
                /* Options without arguments */
                {"help",        no_argument,       NULL, 'h'},
                {"version",     no_argument,       NULL, 'V'},
                {"random",      no_argument,       NULL, 'r'},
                {"endding",     no_argument,       NULL, 'e'},
                {"another",     no_argument,       NULL, 'a'},
                {"show",        no_argument,       NULL, 's'},
                {"another_any", no_argument,       NULL, 'A'},
                {"list",        optional_argument, NULL, 'l'},
                {"mac",         required_argument, NULL, 'm'},
                {NULL, 0, NULL, 0}
        };

        net_info_t	*neti;
        mac_t	*mac;
        mac_t	*mac_faked;

	/* for cdp functionality */
	int	cdpmodeyes = 0;
	char	*S_deviceid;
	char	*S_portid;
	char	*S_software;
	char	*S_platform;
	char	*S_capas;
	char	*S_duplex;
	unsigned int retval;
	struct in_addr	S_ipaddr;
	int atsock;

        int val;

	while ((o = getopt(argc,argv, "o:i:c:v:m:d:t:nhlVaDE:P:C:L:S:U:zZ")) > 0){
	switch(o){
        case 'o':
		lldpspoof_yes=1;
                lldpDeviceID = optarg;
		int len = strlen(lldpDeviceID);
		if(len != 17) {
			// print correct usage
			printf("Correct usage is 17 character device ID for lldp spoofing.  Example:  00:50:60:03:99:CB\n");
			exit (1);
		}
                break;
	case 'i':
		intsp = 1;	
		IfName_temp = malloc(strlen(optarg)*sizeof(char));
		strcpy(IfName_temp,optarg);
		IfNameExt = optarg;
		break;
	case 'c':
		cdpmodeyes=1;
		cdpmode=atol(optarg);
		if (cdpmode==0) 
			printf("VoIP Hopper %s Running in CDP Sniff Mode\n",VERSION);
		else if (cdpmode==1) 
			printf("VoIP Hopper %s Running in CDP Spoof mode\n",VERSION);
		else if (cdpmode==2) 
			printf("VoIP Hopper %s Running in CDP Spoof mode\n",VERSION);
		else {
			printf("CDP mode should be 0, 1, or 2\n");
			exit(1);
		}
		break;
	case 'v':
		vhop_yes = 1;
		if (intsp == 0) {
			print_app_vlan_usage();
			exit(1);
		} else {
			vlan_hop = optarg;
			vvid = atoi(vlan_hop);
			printf("VoIP Hopper %s Running in VLAN Hop mode ~ Trying to hop into VLAN %d\n",VERSION,vvid);
		}
		break;
	case 'h':
		print_help_usage();
		exit(0);
	case 'l':
                if (pcap_findalldevs (&alldevsp, errbuf) < 0) {
                        fprintf(stderr, "%s", errbuf);
                        exit(1);
                }
                while (alldevsp != NULL) {
                        printf("%s\n", alldevsp->name);
                        alldevsp = alldevsp->next;
                }
                exit(0);
        case 'V':
		print_version();
                exit(0);
	case 'm':
		macy = 1;
		if (intsp == 0) {
			print_mac_usage();
			exit(0);
		}
		set_mac = optarg;
		break;
	case 'd':
		RemIfName = optarg;
		remove_interface(RemIfName);
		exit(0);
	case 'n':
		nortel_yes = 1;
		if (intsp != 1) {
			print_nortel_usage();
			exit(1);
		} else if (IfName_temp == NULL) {
			printf("Device is null\nSet the device with -i flag\n");
			exit(1);
		} else {


		}
		break;
	case 'a':
		avaya_yes = 1;
		if (intsp != 1){
			print_avaya_usage();
			exit(1);
		} else if (IfName_temp == NULL) { 
			printf("Device is null\nSet the device with -i flag\n");
			exit(1);
		} else {

			
		}
		break;
	case 't':
		alcatel_yes = 1;
		alcatelmode=atol(optarg);
                if (alcatelmode==0)
                        printf("VoIP Hopper %s Running in Alcatel DHCP Option 43 Spoof mode\n",VERSION);
                else if (alcatelmode==1)
                        printf("VoIP Hopper %s Running in Alcatel LLDP-MED Spoof mode\n",VERSION);
                else if (alcatelmode==2)
                        printf("VoIP Hopper %s Running in Alcatel specify VLAN mode\n",VERSION);
                else {
                        printf("Alcatel mode should be 0, 1, or 2\n");
                        exit(1);
                }

		if (intsp != 1){
                        print_alcateliptouch_usage();
                        exit(1);
                } else if (IfName_temp == NULL) {
                        printf("Device is null\nSet the device with -i flag\n");
                        exit(1);
                } else {


                }
                break;
	case 'D':
		dont_set = 1;
                break;
	case 'E':
		S_deviceid=(char *)malloc(strlen(optarg)+1);
		strcpy(S_deviceid,optarg);
		break;
	case 'P':
		S_portid=(char *)malloc(strlen(optarg)+1);
		strcpy(S_portid,optarg);
		break;
	case 'C':
		S_capas=(char *)malloc(strlen(optarg)+1);
		strcpy(S_capas,optarg);
		break;
	case 'L':
		S_platform=(char *)malloc(strlen(optarg)+1);
		strcpy(S_platform,optarg);
		break;
	case 'S':
		S_software=(char *)malloc(strlen(optarg)+1);
		strcpy(S_software,optarg);
		break;
	case 'U':
		S_duplex=(char *)malloc(strlen(optarg)+1);
		strcpy(S_duplex,optarg);
		break;
	case 'z':
		// Assessment Mode of VoIP Hopper turned on
		assessment_mode = 1;
		break;
	case 'Z':
		debug_yes = 1;
		break;
	default:
		break;
	}
	}

	/* Check to see if we need to change the MAC Address */
	if ((macy == 1) && (dont_set != 1)) {
		srandom(time(NULL));

        	/* Read the MAC */
        	if ((neti = mc_net_info_new(IfName)) == NULL) exit(1);
        	mac = mc_net_info_get_mac(neti);

        	/* Print the current MAC info */
        	print_mac ("Current MAC: ", mac);

        	/* Change the MAC */
        	mac_faked = mc_mac_dup (mac);

		if (show) {
			exit (0);
		} else if (set_mac) {
			if (mc_mac_read_string (mac_faked, set_mac) < 0) exit(1);
		} else if (random) {
			mc_mac_random (mac_faked, 6);
		} else if (endding) {
			mc_mac_random (mac_faked, 3);
		} else {
			mc_mac_next (mac_faked);
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


		if ((cdpmodeyes==0)&&(vhop_yes==0)&&(avaya_yes==0)&&(alcatel_yes==0)){
			exit(1);
		}

	}
	
        if ((assessment_mode==0)&&(cdpmodeyes==0)&&(vhop_yes==0)&&(nortel_yes==0)&&(lldpspoof_yes==0)&&(avaya_yes==0)&&(alcatel_yes==0)){

                print_app_base_usage();
                exit(1);

        }

        /*  Testing, for lldp loop spoof mode */
        if (lldpspoof_yes) {

                spoof_lldp_loop(lldpDeviceID, IfName_temp);

        }

	if((nortel_yes==1)&&(avaya_yes==1)){
		printf("\nPlease select either avaya(-a) or nortel(-n) mode ~ not both:\n\n");
		printf("Example 1:  voiphopper -i eth0 -a\n");
		printf("Example 2:  voiphopper -i eth0 -n\n");
		printf("\n'voiphopper -h' for extended usage\n\n");
                exit(1);
	}
	if ((nortel_yes == 1)&&(alcatel_yes==1)){
		printf("\nPlease select either nortel(-n) or alcatel(-t) mode ~ not both:\n\n");
		printf("Example 1:  voiphopper -i eth0 -n\n");
		printf("Example 2:  voiphopper -i eth0 -t 0|1\n");
		printf("\n'voiphopper -h' for extended usage\n\n");
                exit(1);
	}
	if ((avaya_yes == 1)&&(alcatel_yes==1)){
                printf("\nPlease select either avaya(-a) or alcatel(-t) mode ~ not both:\n\n");
                printf("Example 1:  voiphopper -i eth0 -a\n");
                printf("Example 2:  voiphopper -i eth0 -t 0|1\n");
                printf("\n'voiphopper -h' for extended usage\n\n");
                exit(1);
	}


	if(vhop_yes == 1){

		if((nortel_yes ==1)||(avaya_yes==1)||(cdpmodeyes == 1)){
			printf("VLAN Hop mode specified along with another option.\nPlease specify (-a), (-n), (-c 0|1|2), or (-v VVID)\n\n");
			printf("'voiphopper -h' for more help\n\n");
                	exit(1);
		}
	}

	if(nortel_yes == 1) {

		if(cdpmodeyes == 1){
			printf("Nortel option specified with CDP ~ Please run one or the other\n\n'voiphopper -h' for more help\n\n");
			exit(1);
		}

		printf("Beginning VLAN Hop in Nortel IP Phone Environment\n");
		printf("VoIP Hopper %s Sending DHCP request on %s\n",VERSION,IfName_temp);
		vvid = dhcpclientcall(IfName_temp);

		nvvid2 = &nvvid;
		vvid = *nvvid2;
		if (vvid != 0) {
			vlan_hop = "Not Null";
			nortel_vvid_disc = 1;
		} else {
			/* Exit the program if Nortel VVID not discovered from DHCP server */
			printf("No VVID received from DHCP server ~ VoIP Hopper exiting\n");
			exit(1);
		}

	}

	if(avaya_yes == 1) {

		if(cdpmodeyes == 1){
			printf("Avaya option specified with CDP ~ Please run one or the other\n\n'voiphopper -h' for more help\n\n");
			exit(1);
		}

		printf("Beginning VLAN Hop in Avaya IP Phone Environment\n");
		printf("VoIP Hopper %s Sending DHCP request on %s\n",VERSION,IfName_temp);
		vvid = dhcpclientcall(IfName_temp);

		avvid2 = &avvid;
		vvid = *avvid2;
		if (vvid != 0){
			vlan_hop = "Not Null";
			avaya_vvid_disc = 1;
		} else {
			/* Exit the program if Avaya VVID not discovered from DHCP server */
			printf("No VVID received from DHCP server ~ VoIP Hopper exiting\n");
			exit(1);
		}

	}

        if(alcatel_yes == 1) {

                if(cdpmodeyes == 1){
                        printf("Alcatel option specified with CDP ~ Please run one or the other\n\n'voiphopper -h' for more help\n\n");
                        exit(1);
                }

		if(alcatelmode == 0) {

			/* This mode will spoof alcatel compliant dhcp request for Option 43 */
                	printf("Beginning VLAN Hop in Alcatel IP Phone Environment\n");
                	printf("VoIP Hopper %s Sending DHCP request on %s\n",VERSION,IfName_temp);
                	vvid = dhcpclientcall(IfName_temp);

                	tvvid2 = &tvvid;
                	vvid = *tvvid2;
                	if (vvid != 0){
                        	vlan_hop = "Not Null";
                        	alcatel_vvid_disc = 1;
                	} else {
                        	/* Exit the program if Alcatel VVID not discovered from DHCP server */
                        	printf("No VVID received from DHCP server ~ VoIP Hopper exiting\n");
                        	exit(1);
                	}
		} else if (alcatelmode == 1) {
			/* This mode will spoof LLDP-MED to get VVID, then send an alcatel compliant dhcp request sourced from the new voice sub-interface */
                	//spoof_lldp_loop(lldpDeviceID, IfName_temp);
                	spoof_lldp_loop(set_mac, IfName_temp);
			// Program exit!
			exit(1);

		} else if (alcatelmode == 2) {
			/* This mode will let the user specify a VLAN to hop into (-v VVID), then send an alcatel compliant dhcp request sourced from the new voice sub-interface */
			if(vhop_yes != 1) {
				
				printf("Alcatel VLAN Hop mode specified without -v VVID option.\nExample:  ");
				printf("voiphopper -i eth0 -v 801 -t 2\n");
				exit(1);
			} 

		} else {

			// Do nothing

		}

        }

	if (assessment_mode) {

		if(debug_yes) {
			printf("VoIP Hopper %s assessment mode ~ ",VERSION);
			
		} else {
			printf("VoIP Hopper assessment mode ~ ");
		}

		printf("Select 'q' to quit and 'h' for help menu.\n");

		int rc;
		int arg;

		pthread_t sniffermain_threads[1];
		rc = pthread_create(&sniffermain_threads[0],NULL,sniffer_main,(void *)arg);
		if(rc) {

			printf("Error:  pthread_create error %d\n",rc);
			exit(-1);
		}

		start_ass_ui();
		return(1);

	}

	/* Check to see if cdp sniffing mode is specified */
	if ((vlan_hop == NULL)&&(cdpmode==0)&&(nortel_yes!=1)&&(avaya_yes!=1)&&(lldpspoof_yes==0)) {

		if (IfName_temp == NULL) {

			IfName_temp = pcap_lookupdev(errbuf);

        	        if (IfName_temp == NULL) {

        	                fprintf(stderr, "Couldn't find default device: %s\n",errbuf);
	                        exit(EXIT_FAILURE);
	                }
			printf("Interface not specified - Using first usable default device: ");
			printf("%s\n", IfName_temp);
		}

	        if (pcap_lookupnet(IfName_temp, &net, &mask, errbuf) == -1) {

	                fprintf(stderr, "Couldn't get netmask for device %s.  Enable the interface first and assign an IP address: %s\n", IfName_temp, errbuf);
                	net = 0;
                	mask = 0;
			exit(EXIT_FAILURE);
        	}

        	printf("Capturing CDP Packets on %s\n", IfName_temp);

        	handle = pcap_open_live(IfName_temp, SNAP_LEN, 1, 1000, errbuf);
        	if (handle == NULL) {
        	        fprintf(stderr, "Couldn't open device %s: %s\n", IfName_temp, errbuf);
        	        exit(EXIT_FAILURE);
        	}

        	if (pcap_datalink(handle) != DLT_EN10MB) {
        	        fprintf(stderr, "\n%s is not an Ethernet Interface\n", IfName_temp);
        	        exit(EXIT_FAILURE);
        	}

        	if (pcap_compile(handle, &fp, cdp_filter_exp, 0, net) == -1) {
        	        fprintf(stderr, "Couldn't parse filter %s: %s\n",
        	            cdp_filter_exp, pcap_geterr(handle));
        	        exit(EXIT_FAILURE);
        	}

        	if (pcap_setfilter(handle, &fp) == -1) {
        	        fprintf(stderr, "Couldn't install filter %s: %s\n",
        	            cdp_filter_exp, pcap_geterr(handle));
        	        exit(EXIT_FAILURE);
        	}

		vvid = 0;
		while (vvid == 0) {	
			
			int pcap_return = pcap_next_ex(handle, &header, &packet);
			if (pcap_return <= 0) {
				/* Read timeout of 1 second reached - can later make this a debug statement */
				/* printf("Read timeout in pcap_next_ex ~ Still waiting for CDP packet\n"); */
			} else {
				u_char *args;	
				vvid = get_cdp(args, header, packet);
			}
		}

        	pcap_freecode(&fp);
        	pcap_close(handle);

		/* To create string for new voice interface */
		char vinterface[BUFSIZ];
		snprintf(vinterface, sizeof(vinterface), "%s.%d", IfName_temp, vvid);

		/* Check to make sure interface isn't already configured */
		int retval = pcap_lookupnet(vinterface, &net, &mask, errbuf);
		if (retval == 0) {

			/* Get network address and netmask */
			char *net_str = NULL;
			char *mask_str = NULL;
			struct in_addr tmp_ip;
			struct in_addr tmp_mask;
			memcpy(&tmp_ip.s_addr, &net, sizeof(u_int8_t)*4);
			net_str = inet_ntoa(tmp_ip);
			
			printf("Voice VLAN interface %s is already configured:\n\n",vinterface);

                        if(net_str == NULL) {
                                perror("inet_ntoa error\n");
                                return(-1);
                        } else {
                                printf("Network Address:  %s\n", net_str);
                        }
                        memcpy(&tmp_mask.s_addr, &mask, sizeof(u_int8_t)*4);
                        mask_str = inet_ntoa(tmp_mask);

                        if(mask_str == NULL) {
                                perror("inet_ntoa error\n");
                                return(-1);
                        } else {
                                printf("Netmask:  %s\n",mask_str);
                        }

			printf("\nTo delete interface, run command:\n");
			printf("'voiphopper -d %s'\n\n",vinterface);
			exit(1);
		}

		/* Add the VVID interface */
		create_vlan_interface(IfName_temp,vvid);
		printf("Added VLAN %u to Interface %s\n",vvid, IfName_temp);

                /* Check to see if we need to change the MAC Address for new interface */
                if ((macy == 1)&&(dont_set == 1))  {
                        printf("Changing MAC address for new interface\n");
                        srandom(time(NULL));

                        /* Read the MAC */
                        if ((neti = mc_net_info_new(vinterface)) == NULL) exit(1);
                        mac = mc_net_info_get_mac(neti);

                        /* Print the current MAC info */
                        print_mac_new_interface ("Current MAC: ", mac);

                        /* Change the MAC */
                        mac_faked = mc_mac_dup (mac);

                        if (show) {
                                exit (0);
                        } else if (set_mac) {
                                if (mc_mac_read_string (mac_faked, set_mac) < 0) exit(1);
                        } else if (random) {
                                mc_mac_random (mac_faked, 6);
                        } else if (endding) {
                                mc_mac_random (mac_faked, 3);
                        } else {
                                mc_mac_next (mac_faked);
                        }
		
			/* Set the new MAC */
                        if (mc_net_info_set_mac (neti, mac_faked) >= 0) {
                                /* Re-read the MAC */
                                mc_mac_free (mac_faked);
                                mac_faked = mc_net_info_get_mac(neti);

                                /* Print it */
                                print_mac_new_interface ("Faked MAC:   ", mac_faked);

                                /* Is the same MAC? */
                                if (mc_mac_equal (mac, mac_faked)) {
                                        printf ("It's the same MAC Address!!\n");
                                }

                        }

                        /* Memory free */
                        mc_mac_free (mac);
                        mc_mac_free (mac_faked);
                        mc_net_info_free (neti);

                } else {

			/* Read the MAC */
			if ((neti = mc_net_info_new(vinterface)) == NULL) exit(1);
			mac = mc_net_info_get_mac(neti);

			/* Print the current MAC info */
			print_mac_new_interface ("Current MAC: ", mac);

		}

		printf("Attempting dhcp request for new interface %s\n",vinterface);
		int return_value = dhcpclientcall(vinterface);

	/* Check to see if CDP spoof mode is specified */
	} else if ((cdpmode==1)||(cdpmode==2)) {

		if (intsp == 0) {
			printf("In CDP Spoof Mode, must specify interface\n");
			printf("Example usage:  voiphopper -i eth1 -c 1\n");
			exit(1);
		} else {
			if ((atsock=init_socket_eth(IfName_temp))<=0){
				printf("The interface %s must have a valid IP address in order for the CDP spoofing code to work.\nFirst set the IP address static or via DHCP, and then run again.\n",IfName_temp);
				printf("Could not initialize CDP attack socket\n");
                		exit(1);
			}else{

			}
		}

		if (cdpmode == 2) {
			
	                S_deviceid         = "SEP001EF7289C8E";
			S_portid           = "Port 1";
			S_capas            = "Host";
			S_platform         = "Cisco IP Phone 7971";
			S_software         = "SCCP70.8-3-3SR2S";
			S_duplex           = "1";
		}	

		if (!((S_deviceid!=NULL)
			&& (S_portid!=NULL)
			&& (S_capas!=NULL)
			&& (S_platform!=NULL)
			&& (S_software!=NULL)
			&& (S_duplex!=NULL))) {
				fprintf(stderr,"For CDP Spoof Mode, the following options"
				" are required:\n"
				"	-E <string> (Device ID)\n"
				"	-P <string> (Port ID)\n"
				"	-C <string> (Capabilities)\n"
				"	-L <string> (Platform)\n"
				"	-S <string> (Software)\n"
				"	-U <string> (Duplex)\n"
				"\nExample Usage for SIP Firmware Phone:\nvoiphopper -i eth0 -c 1 -E 'SIP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P003-08-8-00' -U 1\n"
				"Example Usage for SCCP Firmware Phone:\nvoiphopper -i eth0 -c 1 -E 'SEP00070EEA5086' -P 'Port 1' -C Host -L 'Cisco IP Phone 7940' -S 'P00308000700' -U 1\n"
				);
			exit (1);

		} else {


			/* First setup interface to sniff CDP, then we will send CDP */
	                if (pcap_lookupnet(IfName_temp, &net, &mask, errbuf) == -1) {
				fprintf(stderr, "Couldn't get netmask for device %s.  Enable the interface first and assign an IP address: %s\n", IfName_temp, errbuf);
                        	net = 0;
                        	mask = 0;
                        	exit(EXIT_FAILURE);
			}

                	handle = pcap_open_live(IfName_temp, SNAP_LEN, 1, 1000, errbuf);
                	if (handle == NULL) {
                	        fprintf(stderr, "Couldn't open device %s: %s\n", IfName_temp, errbuf);
                	        exit(EXIT_FAILURE);
                	}

                	if (pcap_datalink(handle) != DLT_EN10MB) {
                	        fprintf(stderr, "\n%s is not an Ethernet Interface\n", IfName_temp);
                	        exit(EXIT_FAILURE);
                	}

                	if (pcap_compile(handle, &fp, cdp_filter_exp, 0, net) == -1) {
                	        fprintf(stderr, "Couldn't parse filter %s: %s\n",
                	            cdp_filter_exp, pcap_geterr(handle));
                	        exit(EXIT_FAILURE);
                	}

			if (pcap_setfilter(handle, &fp) == -1) {
                	        fprintf(stderr, "Couldn't install filter %s: %s\n",
                	            cdp_filter_exp, pcap_geterr(handle));
				exit(EXIT_FAILURE);
                	}

	                vvid = 0;
		
			/* First CDP Packet when Phone boots */
			printf("Sending 1st CDP Spoofed packet on %s with CDP packet data:\n",IfName_temp);
			retval = mk_spoof_cdp(S_deviceid,S_portid,S_software,S_platform,S_capas,S_duplex);
                        printf("Made CDP packet of %d bytes - ",retval);

			int retval2;
			retval2 = sendpack_eth(IfName_temp,atsock,cdpframe,retval);
                        printf("Sent CDP packet of %d bytes\n",retval2);

			/* Get the sent packet off the buffer wire*/
			int pcap_return = pcap_next_ex(handle, &header, &packet);

                        while (vvid == 0) {

                                int pcap_return = pcap_next_ex(handle, &header, &packet);

                                if (pcap_return <= 0) {
					/* Read timeout of 1 second reached - can later make this a debug statement */
                                        /* printf("Read timeout in pcap_next_ex ~ Still waiting for CDP packet\n"); */
                                } else {
                                        u_char *args;
                                        vvid = get_cdp(args, header, packet);
                                }
                        }
		
	
			/* Second CDP Packet when Phone boots */
			printf("Sending 2nd CDP Spoofed packet on %s with CDP packet data:\n",IfName_temp);
                        retval = mk_spoof_cdp(S_deviceid,S_portid,S_software,S_platform,S_capas,S_duplex);
                        printf("Made CDP packet of %d bytes - ",retval);

                        retval2 = sendpack_eth(IfName_temp,atsock,cdpframe,retval);
                        printf("Sent CDP packet of %d bytes\n",retval2);

			/* Get the sent packet off the buffer / wire*/
                        pcap_return = pcap_next_ex(handle, &header, &packet);

			while (vvid == 0) {

				int pcap_return = pcap_next_ex(handle, &header, &packet);

				if (pcap_return <= 0) {
					/* Read timeout of 1 second reached - can later make this a debug statement */
                                        /* printf("Read timeout in pcap_next_ex ~ Still waiting for CDP packet\n"); */
					printf("Error in pcap_next_ex\n");
				} else {
					u_char *args;
					vvid = get_cdp(args, header, packet);
				}
			}

                	pcap_freecode(&fp);
                	pcap_close(handle);
			/* End Using pcap */

			/* To create string for new voice interface */
			char vinterface[BUFSIZ];
			snprintf(vinterface, sizeof(vinterface), "%s.%d", IfName_temp, vvid);

			/* Check to make sure interface isn't already configured */
			int retval = pcap_lookupnet(vinterface, &net, &mask, errbuf);
			if (retval == 0) {

	                        /* Get network address and netmask */
				char *net_str = NULL;
                        	char *mask_str = NULL;
                        	struct in_addr tmp_ip;
                        	struct in_addr tmp_mask;
                        	memcpy(&tmp_ip.s_addr, &net, sizeof(u_int8_t)*4);
                        	net_str = inet_ntoa(tmp_ip);

                        	printf("Voice VLAN interface %s is already configured:\n\n",vinterface);

				if(net_str == NULL) {
                                	perror("inet_ntoa error\n");
                                	return(-1);
                        	} else {
                                	printf("Network Address:  %s\n", net_str);
                        	}
                        	
				memcpy(&tmp_mask.s_addr, &mask, sizeof(u_int8_t)*4);
                        	mask_str = inet_ntoa(tmp_mask);

                        	if(mask_str == NULL) {
                                	perror("inet_ntoa error\n");
                                	return(-1);
                        	} else {
                                	printf("Netmask:  %s\n",mask_str);
                        	}


				printf("\nTo delete interface, run command:\n");
                        	printf("'voiphopper -d %s'\n\n",vinterface);
                        	exit(1);

			}

			/* Add the VVID interface */
			create_vlan_interface(IfName_temp, vvid);
			printf("Added VLAN %u to Interface %s\n",vvid, IfName_temp);

	                /* Check to see if we need to change the new MAC Address */
	                if ((macy == 1)&&(dont_set == 1)) {
	                        printf("Changing MAC address for new interface\n");
	                        srandom(time(NULL));

	                        /* Read the MAC */
	                        if ((neti = mc_net_info_new(vinterface)) == NULL) exit(1);
	                        mac = mc_net_info_get_mac(neti);

        	                /* Print the current MAC info */
				print_mac_new_interface ("Current MAC: ", mac);

                        	/* Change the MAC */
                        	mac_faked = mc_mac_dup (mac);

                        	if (show) {
                        	        exit (0);
                        	} else if (set_mac) {
                        	        if (mc_mac_read_string (mac_faked, set_mac) < 0) exit(1);
                        	} else if (random) {
                        	        mc_mac_random (mac_faked, 6);
                        	} else if (endding) {
                        	        mc_mac_random (mac_faked, 3);
                        	} else {
                        	        mc_mac_next (mac_faked);
                        	}

                        	/* Set the new MAC */
                        	if (mc_net_info_set_mac (neti, mac_faked) >= 0) {
                        	        /* Re-read the MAC */
                        	        mc_mac_free (mac_faked);
                        	        mac_faked = mc_net_info_get_mac(neti);

                        	        /* Print it */
                        	        print_mac_new_interface ("Faked MAC:   ", mac_faked);

                        	        /* Is the same MAC? */
                        	        if (mc_mac_equal (mac, mac_faked)) {
                        	                printf ("It's the same MAC Address!!\n");
                        	        }

                        	}

	                        /* Memory free */
	                        mc_mac_free (mac);
	                        mc_mac_free (mac_faked);
	                        mc_net_info_free (neti);

	                } else {

				
                                /* Read the MAC */
                                if ((neti = mc_net_info_new(vinterface)) == NULL) exit(1);
                                mac = mc_net_info_get_mac(neti);

                                /* Print the current MAC info */
                                print_mac_new_interface ("Current MAC: ", mac);

			}

			printf("VoIP Hopper will sleep and then send CDP Packets\n");	
	                printf("Attempting dhcp request for new interface %s\n",vinterface);
			int return_value = dhcpclientcall(vinterface);

			/* Enter a loop in order to send CDP spoofed packet every minute */
			unsigned int ksleeps;
			unsigned int sleepseconds = 60;
			ksleeps = sleep(sleepseconds);
			for ( ; ; ){

				printf("Sending CDP Spoofed packet on %s with CDP packet data:\n",IfName);
                        	retval = mk_spoof_cdp(S_deviceid,S_portid,S_software,S_platform,S_capas,S_duplex);
				printf("Made CDP packet of %d bytes - ",retval);

	                        int retval2;
	                        retval2 = sendpack_eth(IfName,atsock,cdpframe,retval);
				printf("Sent CDP packet of %d bytes\n",retval2);

				printf("Sleeping for 60 seconds before sending another CDP packet\n\n");	
				ksleeps = sleep(sleepseconds);

			}	

		}


	/* This is for Avaya mode, Alcatel mode, Nortel mode, or VLAN Hop mode */
	} else {

		/* To create string for new voice interface */
                snprintf(vinterface, sizeof(vinterface), "%s.%d", IfName_temp, vvid);
		
		/* Check to make sure interface isn't already enabled */
		int retval = pcap_lookupnet(vinterface, &net, &mask, errbuf);

		if (retval == 0) {

			/* Get ip and netmask */
			char *net_str = NULL;
			char *mask_str = NULL;
			struct in_addr tmp_ip;
			struct in_addr tmp_mask;
			memcpy(&tmp_ip.s_addr, &net, sizeof(u_int8_t)*4);
			net_str = inet_ntoa(tmp_ip);

                        printf("Voice VLAN interface %s is already configured:\n\n",vinterface);

			if(net_str == NULL) {
				perror("inet_ntoa error\n");
				return(-1);
			} else {
				printf("Network Address:  %s\n", net_str);
			}
			memcpy(&tmp_mask.s_addr, &mask, sizeof(u_int8_t)*4);
			mask_str = inet_ntoa(tmp_mask);

			if(mask_str == NULL) {
				perror("inet_ntoa error\n");
				return(-1);
			} else {
				printf("Netmask:  %s\n",mask_str);
			}
			
			printf("\nTo delete interface, run command:\n");
			printf("'voiphopper -d %s'\n\n",vinterface);
			exit(1);
		}

		/* Add the VVID Interface */
		create_vlan_interface(IfName_temp,vvid);
		printf("Added VLAN %u to Interface %s\n",vvid, IfName_temp);

	        /* Check to see if we need to change the MAC Address */
	        if (macy == 1) {
			printf("Changing MAC address for new interface\n");
	                srandom(time(NULL));

	                /* Read the MAC */
	                if ((neti = mc_net_info_new(vinterface)) == NULL) exit(1);
	                mac = mc_net_info_get_mac(neti);

	                /* Print the current MAC info */
	                print_mac_new_interface ("Current MAC: ", mac);

	                /* Change the MAC */
	                mac_faked = mc_mac_dup (mac);

	                if (show) {
	                        exit (0);
	                } else if (set_mac) {
	                        if (mc_mac_read_string (mac_faked, set_mac) < 0) exit(1);
	                } else if (random) {
	                        mc_mac_random (mac_faked, 6);
	                } else if (endding) {
	                        mc_mac_random (mac_faked, 3);
	                } else {
	                        mc_mac_next (mac_faked);
	                }

	                /* Set the new MAC */
	                if (mc_net_info_set_mac (neti, mac_faked) >= 0) {
	                        /* Re-read the MAC */
	                        mc_mac_free (mac_faked);
	                        mac_faked = mc_net_info_get_mac(neti);

	                        /* Print it */
	                        print_mac_new_interface ("Faked MAC:   ", mac_faked);

	                        /* Is the same MAC? */
	                        if (mc_mac_equal (mac, mac_faked)) {
	                                printf ("It's the same MAC Address!!\n");
	                        }

	                }

	                /* Memory free */
	                mc_mac_free (mac);
	                mc_mac_free (mac_faked);
	                mc_net_info_free (neti);

	        }

		// Calling dhcp client for new voice interface 
		int return_value = dhcpclientcall(vinterface);

	}

return 0;
}
