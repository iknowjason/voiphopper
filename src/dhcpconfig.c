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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <net/route.h>
#include <net/if.h>
#include <arpa/nameser.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <resolv.h>
#include <netdb.h>
#include "kversion.h"
#include "pathnames.h"
#include "dhcpclient.h"

extern	int			dhcpSocket;
extern	int			prev_ip_addr;
extern	int			Window;
extern  int			SetDHCPDefaultRoutes;
extern	int			TestCase;
extern	int			DebugFlag;
extern	int			SetDomainName;
extern	int			SetHostName;
extern	int			ReplResolvConf;
extern	int			ReplNISConf;
extern	int			ReplNTPConf;
extern	int			IfName_len,IfNameExt_len;
extern	char			*IfName,*IfNameExt,*Cfilename,*ConfigDir;
extern	char			**ProgramEnviron;
extern	unsigned char		ClientHwAddr[ETH_ALEN],*ClientID;
extern	struct in_addr		default_router;
extern	dhcpInterface		DhcpIface;
extern	dhcpOptions		DhcpOptions;
extern	const dhcpMessage	*DhcpMsgRecv;

int	arpInform();

char	hostinfo_file[128];
int	resolv_renamed=0; 
int	yp_renamed=0;
int	ntp_renamed=0;  

/* Note: Legths initialised to negative to allow us to distinguish between "empty" and "not set" */
char InitialHostName[HOSTNAME_MAX_LEN];
int InitialHostName_len=-1;
char InitialDomainName[HOSTNAME_MAX_LEN];
int InitialDomainName_len=-1;

/*****************************************************************************/
char *cleanmetas(cstr) /* this is to clean single quotes out of DHCP strings */
char *cstr;		/* replace single quotes with space */
{
  register char *c=cstr;
  do
    if ( *c == 39 ) *c = ' ';
  while ( *c++ );
  return cstr;
}
/*****************************************************************************/
void execute_on_change(prm)
char *prm;
{
#ifdef EMBED
  if ( vfork() == 0 )
#else
  if ( fork() == 0 )
#endif
    {
      char *argc[5],exec_on_change[128];
      if ( Cfilename ) {
	/* snprintf(exec_on_change,sizeof(exec_on_change),Cfilename); */
	/* Temporarily commented out because of compiler warning, format not a string literal and no format arguments */
      } else {
	snprintf(exec_on_change,sizeof(exec_on_change),EXEC_ON_CHANGE,ConfigDir);
      }
      argc[0]=exec_on_change;
      argc[1]=hostinfo_file;
      argc[2]=prm;
      if ( DebugFlag )
        argc[3]="-d";
      else
        argc[3]=NULL;
      argc[4]=NULL;
      if ( execve(exec_on_change,argc,ProgramEnviron) && errno != ENOENT )
	syslog(LOG_ERR,"error executing \"%s %s %s\": %m\n",
	exec_on_change,hostinfo_file,prm);
      exit(0);
    }
}
/*****************************************************************************/
unsigned long getgenmask(ip_in)		/* this is to guess genmask	*/
unsigned long ip_in;			/* from network address		*/
{
  unsigned long t,p=ntohl(ip_in);
  if ( IN_CLASSA(p) )
    t= ~IN_CLASSA_NET;
  else
    {
      if ( IN_CLASSB(p) )
	t= ~IN_CLASSB_NET;
      else
	{
	  if ( IN_CLASSC(p) )
	    t= ~IN_CLASSC_NET;
	  else
	    t=0;
	}
    }
  while ( t&p ) t>>=1;
  return htonl(~t);
}
/*****************************************************************************/
int setDefaultRoute(route_addr)
char *route_addr;
{
struct	rtentry		rtent;
struct	sockaddr_in	*p;

memset(&rtent,0,sizeof(struct rtentry));
p			=	(struct sockaddr_in *)&rtent.rt_dst;
p->sin_family		=	AF_INET;
p->sin_addr.s_addr	=	0;
p			=	(struct sockaddr_in *)&rtent.rt_gateway;
p->sin_family		=	AF_INET;
memcpy(&p->sin_addr.s_addr,route_addr,4);
p			=	(struct sockaddr_in *)&rtent.rt_genmask;
p->sin_family		=	AF_INET;
p->sin_addr.s_addr	=	0;
#ifdef OLD_LINUX_VERSION
  rtent.rt_dev		=	IfName;
#else
  rtent.rt_dev		=	IfNameExt;
#endif
rtent.rt_metric	        =	1;
rtent.rt_window		=	Window;
rtent.rt_flags	        =	RTF_UP|RTF_GATEWAY|(Window ? RTF_WINDOW : 0);
if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == -1 )
  {
    if ( errno == ENETUNREACH )    /* possibly gateway is over the bridge */
      {                            /* try adding a route to gateway first */
	memset(&rtent,0,sizeof(struct rtentry));
	p			=	(struct sockaddr_in *)&rtent.rt_dst;
	p->sin_family		=	AF_INET;
	memcpy(&p->sin_addr.s_addr,route_addr,4);
	p			=	(struct sockaddr_in *)&rtent.rt_gateway;
	p->sin_family		=	AF_INET;
	p->sin_addr.s_addr	=	0;
	p			=	(struct sockaddr_in *)&rtent.rt_genmask;
	p->sin_family		=	AF_INET;
	p->sin_addr.s_addr	=	0xffffffff;
#ifdef OLD_LINUX_VERSION
	rtent.rt_dev		=	IfName;
#else
	rtent.rt_dev		=	IfNameExt;
#endif
	rtent.rt_metric     =	  0;
	rtent.rt_flags      =	  RTF_UP|RTF_HOST;
	if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == 0 )
	  {
	    memset(&rtent,0,sizeof(struct rtentry));
	    p			=	(struct sockaddr_in *)&rtent.rt_dst;
	    p->sin_family	=	AF_INET;
	    p->sin_addr.s_addr	=	0;
	    p			=	(struct sockaddr_in *)&rtent.rt_gateway;
	    p->sin_family	=	AF_INET;
	    memcpy(&p->sin_addr.s_addr,route_addr,4);
	    p			=	(struct sockaddr_in *)&rtent.rt_genmask;
	    p->sin_family	=	AF_INET;
	    p->sin_addr.s_addr	=	0;
#ifdef OLD_LINUX_VERSION
	    rtent.rt_dev	=	IfName;
#else
	    rtent.rt_dev	=	IfNameExt;
#endif
	    rtent.rt_metric	=	1;
	    rtent.rt_window	=	Window;
	    rtent.rt_flags	=	RTF_UP|RTF_GATEWAY|(Window ? RTF_WINDOW : 0);
	    if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) == -1 )
	      {
		syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
		return -1;
	      }
	  }
      }
    else
      {
	syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
	return -1;
      }
  }
return 0;
}
/*****************************************************************************/
int dhcpConfig()
{
  int i;
  FILE *f;
  char hostinfo_file_old[128];
  struct ifreq		ifr;
  struct rtentry	rtent;
#ifdef OLD_LINUX_VERSION
  struct sockaddr_pkt	sap;
#endif
  struct sockaddr_in	*p = (struct sockaddr_in *)&(ifr.ifr_addr);
  struct hostent *hp=NULL;
  char *dname=NULL;
  int dname_len=0;

  if ( TestCase ) goto tsc;
  memset(&ifr,0,sizeof(struct ifreq));
#ifdef OLD_LINUX_VERSION
  memcpy(ifr.ifr_name,IfName,IfName_len);
#else
  memcpy(ifr.ifr_name,IfNameExt,IfNameExt_len);
#endif
  p->sin_family = AF_INET;
  p->sin_addr.s_addr = DhcpIface.ciaddr;
  if ( ioctl(dhcpSocket,SIOCSIFADDR,&ifr) == -1 )  /* setting IP address */
    {
      syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFADDR: %m\n");
      return -1;
    }
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  if ( ioctl(dhcpSocket,SIOCSIFNETMASK,&ifr) == -1 )  /* setting netmask */
    {
      p->sin_addr.s_addr = 0xffffffff; /* try 255.255.255.255 */
      if ( ioctl(dhcpSocket,SIOCSIFNETMASK,&ifr) == -1 )
	{
	  syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFNETMASK: %m\n");
	  return -1;
	}
    }
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[broadcastAddr],4);
  if ( ioctl(dhcpSocket,SIOCSIFBRDADDR,&ifr) == -1 ) /* setting broadcast address */
    syslog(LOG_ERR,"dhcpConfig: ioctl SIOCSIFBRDADDR: %m\n");

  /* setting local route - not needed on later kernels  */
#ifdef OLD_LINUX_VERSION
  memset(&rtent,0,sizeof(struct rtentry));
  p			=	(struct sockaddr_in *)&rtent.rt_dst;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  p->sin_addr.s_addr	&=	DhcpIface.ciaddr;
  p			=	(struct sockaddr_in *)&rtent.rt_gateway;
  p->sin_family		=	AF_INET;
  p->sin_addr.s_addr	=	0;
  p			=	(struct sockaddr_in *)&rtent.rt_genmask;
  p->sin_family		=	AF_INET;
  memcpy(&p->sin_addr.s_addr,DhcpOptions.val[subnetMask],4);
  rtent.rt_dev		=	IfName;
  rtent.rt_metric     	=	1;
  rtent.rt_flags      	=	RTF_UP;
  if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) )
    syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
#endif

  for (i=0;i<DhcpOptions.len[staticRoute];i+=8)
    {  /* setting static routes */
      struct sockaddr_in *dstp; 
      struct sockaddr_in *gwp; 
      struct sockaddr_in *mskp; 
      memset(&rtent,0,sizeof(struct rtentry));
      dstp		=	(struct sockaddr_in *)&rtent.rt_dst;
      dstp->sin_family	=	AF_INET;
      memcpy(&dstp->sin_addr.s_addr,((char *)DhcpOptions.val[staticRoute])+i,4);
      gwp		=	(struct sockaddr_in *)&rtent.rt_gateway;
      gwp->sin_family	=	AF_INET;
      memcpy(&gwp->sin_addr.s_addr,((char *)DhcpOptions.val[staticRoute])+i+4,4);
      mskp		=	(struct sockaddr_in *)&rtent.rt_genmask;
      mskp->sin_family	=	AF_INET;
      mskp->sin_addr.s_addr = getgenmask(dstp->sin_addr.s_addr);
      rtent.rt_flags	=	RTF_UP|RTF_GATEWAY;
      if ( mskp->sin_addr.s_addr == 0xffffffff ) rtent.rt_flags |= RTF_HOST;

#ifdef OLD_LINUX_VERSION
      rtent.rt_dev	      =	  IfName;
#else
      rtent.rt_dev	      =	  IfNameExt;
#endif
      rtent.rt_metric     =	  1;
      if ( ioctl(dhcpSocket,SIOCADDRT,&rtent) )
	syslog(LOG_ERR,"dhcpConfig: ioctl SIOCADDRT: %m\n");
    }

  if ( SetDHCPDefaultRoutes )
    {
      if ( DhcpOptions.len[routersOnSubnet] > 3 )
	for (i=0;i<DhcpOptions.len[routersOnSubnet];i+=4)
	  setDefaultRoute(DhcpOptions.val[routersOnSubnet]);
    }
  else
    if ( default_router.s_addr > 0 ) setDefaultRoute((char *)&(default_router.s_addr));

  /* rebind dhcpSocket after changing ip address to avoid problems with 2.0 kernels */
#ifdef OLD_LINUX_VERSION
  memset(&sap,0,sizeof(sap));
  sap.spkt_family = AF_INET;
  sap.spkt_protocol = htons(ETH_P_ALL);
  memcpy(sap.spkt_device,IfName,IfName_len);
  if ( bind(dhcpSocket,(void*)&sap,sizeof(struct sockaddr)) == -1 )
    syslog(LOG_ERR,"dhcpConfig: bind: %m\n");
#endif  

  arpInform();
  if ( DebugFlag )
    printf("VoIP Hopper dhcp client:  received IP address for %s: %u.%u.%u.%u\n",
    IfName,
    ((unsigned char *)&DhcpIface.ciaddr)[0],
    ((unsigned char *)&DhcpIface.ciaddr)[1],
    ((unsigned char *)&DhcpIface.ciaddr)[2],
    ((unsigned char *)&DhcpIface.ciaddr)[3]);
  if ( ReplResolvConf )
    {
      resolv_renamed=1+rename(RESOLV_CONF,""RESOLV_CONF".sv");
      f=fopen(RESOLV_CONF,"w");
      if ( f )
	{
	  int i;
#if 0
	  if ( DhcpOptions.len[nisDomainName] )
	    fprintf(f,"domain %s\n",(char *)DhcpOptions.val[nisDomainName]);
	  else
	    if ( DhcpOptions.len[domainName] )
	      fprintf(f,"domain %s\n",(char *)DhcpOptions.val[domainName]);
#endif
	  for (i=0;i<DhcpOptions.len[dns];i+=4)
	    fprintf(f,"nameserver %u.%u.%u.%u\n",
	    ((unsigned char *)DhcpOptions.val[dns])[i],
	    ((unsigned char *)DhcpOptions.val[dns])[i+1],
	    ((unsigned char *)DhcpOptions.val[dns])[i+2],
	    ((unsigned char *)DhcpOptions.val[dns])[i+3]);
#if 0
	  if ( DhcpOptions.len[nisDomainName] + DhcpOptions.len[domainName] )
	    {
	      fprintf(f,"search");
	      if ( DhcpOptions.len[nisDomainName] )
	        fprintf(f," %s",(char *)DhcpOptions.val[nisDomainName]);
	      if ( DhcpOptions.len[domainName] )
	        fprintf(f," %s",(char *)DhcpOptions.val[domainName]);
	      fprintf(f,"\n");
	    }
#else
	  if ( DhcpOptions.len[domainName] )
	    fprintf(f,"search %s\n",(char *)DhcpOptions.val[domainName]);
#endif
	  fclose(f);
	}
      else
	syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");

   /* moved the next section of code from before to after we've created
    * resolv.conf. See below for explanation. <poeml@suse.de>
    * res_init() is normally called from within the first function of the
    * resolver which is called. Here, we want resolv.conf to be
    * reread. Otherwise, we won't be able to find out about our hostname,
    * because the resolver won't notice the change in resolv.conf */
      (void)res_init();
    }
  if ( ReplNISConf )
    {
      yp_renamed=1+rename(NIS_CONF,""NIS_CONF".sv");
      f=fopen(NIS_CONF,"w");
      if ( f )
	{
	  int i;
	  char *domain=NULL;
	  if ( DhcpOptions.len[nisDomainName] )
	    domain=(char *)DhcpOptions.val[nisDomainName];
	  else
	    domain=(char *)DhcpOptions.val[domainName];
	  for (i=0;i<DhcpOptions.len[nisServers];i+=4)
	    fprintf(f,"domain %s server %u.%u.%u.%u\n",(domain?domain:"localdomain"),
	    ((unsigned char *)DhcpOptions.val[nisServers])[i],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+1],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+2],
	    ((unsigned char *)DhcpOptions.val[nisServers])[i+3]);
	  if ( !DhcpOptions.len[nisServers] )
	    fprintf(f,"domain %s broadcast\n", (domain?domain:"localdomain"));
	  fclose(f);
	}
      else
	syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");
    }
  if ( ReplNTPConf )
    {
      ntp_renamed=1+rename(NTP_CONF,""NTP_CONF".sv");
      f=fopen(NTP_CONF,"w");
      if ( f )
 	{
 	  int net, mask;
 	  memcpy(&mask,DhcpOptions.val[subnetMask],4);
 	  net = DhcpIface.ciaddr & mask;

 	  /* Note: Revise drift/log file names and stratum for local clock */
 	  fprintf(f,"restrict default noquery notrust nomodify\n");
 	  fprintf(f,"restrict 127.0.0.1\n");
 	  fprintf(f,"restrict %u.%u.%u.%u mask %u.%u.%u.%u\n",
 		  ((unsigned char *)&net)[0],
 		  ((unsigned char *)&net)[1],
 		  ((unsigned char *)&net)[2],
 		  ((unsigned char *)&net)[3],
 		  ((unsigned char *)&mask)[0],
 		  ((unsigned char *)&mask)[1],
 		  ((unsigned char *)&mask)[2],
 		  ((unsigned char *)&mask)[3]);
 	  if ( DhcpOptions.len[ntpServers]>=4 )
	    {
	      int i;
	      char addr[4*3+3*1+1];
	      for (i=0;i<DhcpOptions.len[ntpServers];i+=4)
		{
		  snprintf(addr,sizeof(addr),"%u.%u.%u.%u",
		  ((unsigned char *)DhcpOptions.val[ntpServers])[i],
		  ((unsigned char *)DhcpOptions.val[ntpServers])[i+1],
		  ((unsigned char *)DhcpOptions.val[ntpServers])[i+2],
		  ((unsigned char *)DhcpOptions.val[ntpServers])[i+3]);
		  fprintf(f,"restrict %s\nserver %s\n",addr,addr);
		}
 	    }
	  else
	    {		/* No servers found, use local clock */
	      fprintf(f, "fudge 127.127.1.0 stratum 3\n");
 	      fprintf(f, "server 127.127.1.0\n");
	    }
 	  fprintf(f, "driftfile /etc/ntp.drift\n");
 	  fprintf(f, "logfile /var/log/ntp.log\n");
 	  fclose(f);
 	}
       else
 	syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");
     }
  if ( SetHostName )
    {
      if ( ! DhcpOptions.len[hostName] )
	{
	  hp=gethostbyaddr((char *)&DhcpIface.ciaddr,
	  sizeof(DhcpIface.ciaddr),AF_INET);
	  if ( hp )
	    {
	      dname=hp->h_name;
	      while ( *dname > 32 )
#if 0
		if ( *dname == '.' )
		  break;
		else
#endif
		  dname++;
	      dname_len=dname-hp->h_name;
	      DhcpOptions.val[hostName]=(char *)malloc(dname_len+1);
	      DhcpOptions.len[hostName]=dname_len;
	      memcpy((char *)DhcpOptions.val[hostName],
	      hp->h_name,dname_len);
	      ((char *)DhcpOptions.val[hostName])[dname_len]=0;
	      DhcpOptions.num++;
	    }
	}
      if ( InitialHostName_len<0 && gethostname(InitialHostName,sizeof(InitialHostName))==0 )
	{
	  InitialHostName_len=strlen(InitialHostName);
	  if ( DebugFlag )
	    fprintf(stdout,"dhcpcd: orig hostname = %s\n",InitialHostName);
	}
      if ( DhcpOptions.len[hostName] )
        {
          sethostname(DhcpOptions.val[hostName],DhcpOptions.len[hostName]);
	  if ( DebugFlag )
	    fprintf(stdout,"dhcpcd: your hostname = %s\n",
	    (char *)DhcpOptions.val[hostName]);
	}
    }
  if ( SetDomainName )
    {
      if ( InitialDomainName_len<0 && getdomainname(InitialDomainName,sizeof(InitialDomainName))==0 )
	{
	  InitialDomainName_len=strlen(InitialDomainName);
	  if ( DebugFlag )
	    fprintf(stdout,"dhcpcd: orig domainname = %s\n",InitialDomainName);
	}
#if 0
      if ( DhcpOptions.len[nisDomainName] )
        {
          setdomainname(DhcpOptions.val[nisDomainName],
		      DhcpOptions.len[nisDomainName]);
	  if ( DebugFlag )
	    fprintf(stdout,"dhcpcd: your domainname = %s\n",
		(char *)DhcpOptions.val[nisDomainName]);
        }
      else
        {
#endif
	  if ( ! DhcpOptions.len[domainName] )
	    {
	      if ( ! hp )
		hp=gethostbyaddr((char *)&DhcpIface.ciaddr,
		sizeof(DhcpIface.ciaddr),AF_INET);
	      if ( hp )
		{
		  dname=hp->h_name;
		  while ( *dname > 32 )
		    if ( *dname == '.' )
		      {
			dname++;
		        break;
		      }
		    else
		      dname++;
		  dname_len=strlen(dname);
		  if ( dname_len )
		    {
		      DhcpOptions.val[domainName]=(char *)malloc(dname_len+1);
		      DhcpOptions.len[domainName]=dname_len;
		      memcpy((char *)DhcpOptions.val[domainName],
		      dname,dname_len);
		      ((char *)DhcpOptions.val[domainName])[dname_len]=0;
		      DhcpOptions.num++;
		    }
		}
	    }
          if ( DhcpOptions.len[domainName] )
            {
	      setdomainname(DhcpOptions.val[domainName],
		DhcpOptions.len[domainName]);
	      if ( DebugFlag )
		fprintf(stdout,"dhcpcd: your domainname = %s\n",
		(char *)DhcpOptions.val[domainName]);
	    }
#if 0
	}
#endif
    }
tsc:
  memset(DhcpIface.version,0,sizeof(DhcpIface.version));
  strncpy(DhcpIface.version,VERSION,sizeof(DhcpIface.version));
  snprintf(hostinfo_file_old,sizeof(hostinfo_file_old),DHCP_CACHE_FILE,ConfigDir,IfNameExt);
  i=open(hostinfo_file_old,O_WRONLY|O_CREAT|O_TRUNC,S_IRUSR+S_IWUSR);
  if ( i == -1 ||
      write(i,(char *)&DhcpIface,sizeof(dhcpInterface)) == -1 ||
      close(i) == -1 )
    syslog(LOG_ERR,"dhcpConfig: open/write/close: %m\n");
  snprintf(hostinfo_file,sizeof(hostinfo_file),DHCP_HOSTINFO,ConfigDir,IfNameExt);
  snprintf(hostinfo_file_old,sizeof(hostinfo_file_old),""DHCP_HOSTINFO".old",ConfigDir,IfNameExt);
  rename(hostinfo_file,hostinfo_file_old);
  f=fopen(hostinfo_file,"w");
  if ( f )
    {
      int b,c;
      memcpy(&b,DhcpOptions.val[subnetMask],4);
      c = DhcpIface.ciaddr & b;
      fprintf(f,"\
IPADDR=%u.%u.%u.%u\n\
NETMASK=%u.%u.%u.%u\n\
NETWORK=%u.%u.%u.%u\n\
BROADCAST=%u.%u.%u.%u\n",
((unsigned char *)&DhcpIface.ciaddr)[0],
((unsigned char *)&DhcpIface.ciaddr)[1],
((unsigned char *)&DhcpIface.ciaddr)[2],
((unsigned char *)&DhcpIface.ciaddr)[3],
((unsigned char *)DhcpOptions.val[subnetMask])[0],
((unsigned char *)DhcpOptions.val[subnetMask])[1],
((unsigned char *)DhcpOptions.val[subnetMask])[2],
((unsigned char *)DhcpOptions.val[subnetMask])[3],
((unsigned char *)&c)[0],
((unsigned char *)&c)[1],
((unsigned char *)&c)[2],
((unsigned char *)&c)[3],
((unsigned char *)DhcpOptions.val[broadcastAddr])[0],
((unsigned char *)DhcpOptions.val[broadcastAddr])[1],
((unsigned char *)DhcpOptions.val[broadcastAddr])[2],
((unsigned char *)DhcpOptions.val[broadcastAddr])[3]);
      if ( DhcpOptions.len[routersOnSubnet] > 3 )
	{
	  fprintf(f,"\
GATEWAY=%u.%u.%u.%u",
((unsigned char *)DhcpOptions.val[routersOnSubnet])[0],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[1],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[2],
((unsigned char *)DhcpOptions.val[routersOnSubnet])[3]);
	  for (i=4;i<DhcpOptions.len[routersOnSubnet];i+=4)
  	    fprintf(f,",%u.%u.%u.%u",
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[1+i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[2+i],
	    ((unsigned char *)DhcpOptions.val[routersOnSubnet])[3+i]);
	}
if ( DhcpOptions.len[staticRoute] )
  {
    fprintf(f,"\nROUTE=%u.%u.%u.%u,%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[staticRoute])[0],
    ((unsigned char *)DhcpOptions.val[staticRoute])[1],
    ((unsigned char *)DhcpOptions.val[staticRoute])[2],
    ((unsigned char *)DhcpOptions.val[staticRoute])[3],
    ((unsigned char *)DhcpOptions.val[staticRoute])[4],
    ((unsigned char *)DhcpOptions.val[staticRoute])[5],
    ((unsigned char *)DhcpOptions.val[staticRoute])[6],
    ((unsigned char *)DhcpOptions.val[staticRoute])[7]);
    for (i=8;i<DhcpOptions.len[staticRoute];i+=8)
    fprintf(f,",%u.%u.%u.%u,%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[staticRoute])[i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[1+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[2+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[3+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[4+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[5+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[6+i],
    ((unsigned char *)DhcpOptions.val[staticRoute])[7+i]);
  }
if ( DhcpOptions.len[hostName] )
  fprintf(f,"\nHOSTNAME=\'%s\'",cleanmetas((char *)DhcpOptions.val[hostName]));
if ( DhcpOptions.len[domainName] )
  fprintf(f,"\nDOMAIN=\'%s\'",cleanmetas((char *)DhcpOptions.val[domainName]));
if ( DhcpOptions.len[nisDomainName] )
  fprintf(f,"\nNISDOMAIN=\'%s\'",cleanmetas((char *)DhcpOptions.val[nisDomainName]));
if ( DhcpOptions.len[rootPath] )
  fprintf(f,"\nROOTPATH=\'%s\'",cleanmetas((char *)DhcpOptions.val[rootPath]));
fprintf(f,"\n\
DNS=%u.%u.%u.%u",
((unsigned char *)DhcpOptions.val[dns])[0],
((unsigned char *)DhcpOptions.val[dns])[1],
((unsigned char *)DhcpOptions.val[dns])[2],
((unsigned char *)DhcpOptions.val[dns])[3]);
for (i=4;i<DhcpOptions.len[dns];i+=4)
  fprintf(f,",%u.%u.%u.%u",
  ((unsigned char *)DhcpOptions.val[dns])[i],
  ((unsigned char *)DhcpOptions.val[dns])[1+i],
  ((unsigned char *)DhcpOptions.val[dns])[2+i],
  ((unsigned char *)DhcpOptions.val[dns])[3+i]);
if ( DhcpOptions.len[ntpServers]>=4 )
  {
    fprintf(f,"\nNTPSERVERS=%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[ntpServers])[0],
    ((unsigned char *)DhcpOptions.val[ntpServers])[1],
    ((unsigned char *)DhcpOptions.val[ntpServers])[2],
    ((unsigned char *)DhcpOptions.val[ntpServers])[3]);
    for (i=4;i<DhcpOptions.len[ntpServers];i+=4)
      fprintf(f,",%u.%u.%u.%u",
      ((unsigned char *)DhcpOptions.val[ntpServers])[i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[1+i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[2+i],
      ((unsigned char *)DhcpOptions.val[ntpServers])[3+i]);
  }
if ( DhcpOptions.len[nisServers]>=4 )
  {
    fprintf(f,"\nNISSERVERS=%u.%u.%u.%u",
    ((unsigned char *)DhcpOptions.val[nisServers])[0],
    ((unsigned char *)DhcpOptions.val[nisServers])[1],
    ((unsigned char *)DhcpOptions.val[nisServers])[2],
    ((unsigned char *)DhcpOptions.val[nisServers])[3]);
    for (i=4;i<DhcpOptions.len[nisServers];i+=4)
      fprintf(f,",%u.%u.%u.%u",
      ((unsigned char *)DhcpOptions.val[nisServers])[i],
      ((unsigned char *)DhcpOptions.val[nisServers])[1+i],
      ((unsigned char *)DhcpOptions.val[nisServers])[2+i],
      ((unsigned char *)DhcpOptions.val[nisServers])[3+i]);
  }
fprintf(f,"\n\
DHCPSID=%u.%u.%u.%u\n\
DHCPGIADDR=%u.%u.%u.%u\n\
DHCPSIADDR=%u.%u.%u.%u\n\
DHCPCHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n\
DHCPSHADDR=%02X:%02X:%02X:%02X:%02X:%02X\n\
DHCPSNAME=\'%s\'\n\
LEASETIME=%u\n\
RENEWALTIME=%u\n\
REBINDTIME=%u\n\
INTERFACE=\'%s\'\n\
CLASSID=\'%s\'\n",
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[0],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[1],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[2],
((unsigned char *)DhcpOptions.val[dhcpServerIdentifier])[3],
((unsigned char *)&DhcpMsgRecv->giaddr)[0],
((unsigned char *)&DhcpMsgRecv->giaddr)[1],
((unsigned char *)&DhcpMsgRecv->giaddr)[2],
((unsigned char *)&DhcpMsgRecv->giaddr)[3],
((unsigned char *)&DhcpMsgRecv->siaddr)[0],
((unsigned char *)&DhcpMsgRecv->siaddr)[1],
((unsigned char *)&DhcpMsgRecv->siaddr)[2],
((unsigned char *)&DhcpMsgRecv->siaddr)[3],
ClientHwAddr[0],
ClientHwAddr[1],
ClientHwAddr[2],
ClientHwAddr[3],
ClientHwAddr[4],
ClientHwAddr[5],
DhcpIface.shaddr[0],
DhcpIface.shaddr[1],
DhcpIface.shaddr[2],
DhcpIface.shaddr[3],
DhcpIface.shaddr[4],
DhcpIface.shaddr[5],
cleanmetas(DhcpMsgRecv->sname),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpIPaddrLeaseTime]),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpT1value]),
ntohl(*(unsigned int *)DhcpOptions.val[dhcpT2value]),
IfNameExt,
DhcpIface.class_id);
      if ( ClientID )
	fprintf(f,"CLIENTID=\'%s\'\n",ClientID);
      else
	fprintf(f,"CLIENTID=%02X:%02X:%02X:%02X:%02X:%02X\n",
DhcpIface.client_id[3],DhcpIface.client_id[4],DhcpIface.client_id[5],
DhcpIface.client_id[6],DhcpIface.client_id[7],DhcpIface.client_id[8]);
      fclose(f);
    }
  else
    syslog(LOG_ERR,"dhcpConfig: fopen: %m\n");
#if 0
  if ( Cfilename )
    if ( fork() == 0 )
      {
	char *argc[2];
	argc[0]=Cfilename;
	argc[1]=NULL;
	if ( execve(Cfilename,argc,ProgramEnviron) )
	  syslog(LOG_ERR,"error executing \"%s\": %m\n",
	  Cfilename);
	printf("hit exit 2\n");
	exit(0);
      }
#endif
  if ( DhcpIface.ciaddr == prev_ip_addr )
    execute_on_change("up");
  else					/* IP address has changed */
    {
      execute_on_change("new");
      prev_ip_addr=DhcpIface.ciaddr;
    }
  if ( *(unsigned int *)DhcpOptions.val[dhcpIPaddrLeaseTime] == 0xffffffff )
    {
      syslog(LOG_INFO,"infinite IP address lease time. Exiting\n");
	printf("hit exit 3\n");
      exit(0);
    }
  return 0;
}
/*****************************************************************************/
