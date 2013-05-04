#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <rpc/types.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <errno.h>

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
#include <pthread.h>

#define SIZE_ETHERNET 14

#define SIZE_VLAN 4

#define SNAP_LEN 1518

#define VERSION		"2.04"

#define APP_NAME		"voiphopper"

#define SIZE_ETHERNET 14
