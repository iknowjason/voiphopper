/* ICMP enum for libpackets
 *
 * $Id: enum.c,v 1.2 2001/06/16 18:17:31 fx Exp $
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <time.h>

#include "protocols.h"
#include "packets.h"
#include "enum.h"

enum_target_t	*enum_anchor;

void enum_free() {
    enum_target_t	*c,*c2;

    if ((c=enum_anchor)==NULL) return;
    while (c!=NULL) {
	c2=c;
	c=c->next;
	free(c2);
    }
}

int enum_known(struct in_addr *addr) {
    enum_target_t	*c;

    if ((c=enum_anchor)==NULL) return 0;
    while (c!=NULL) {
	if (memcmp(&(c->addr),addr,4)==0) return 1;
	c=c->next;
    }
    return 0;
}

int enum_print() {
    enum_target_t	*c;

    if ((c=enum_anchor)==NULL) return 0;
    while (c!=NULL) {
	printf("%s\n",inet_ntoa(c->addr));
	c=c->next;
    }
    return 0;
}

/* returns the number of valid targets or -1 on error 
 *
 * dest		is the destination in one of the following notations
 * 		- FQDN (www.targets.com)
 * 		- IP-Address (192.168.1.1)
 * 		- IP/Netmask (192.168.1.0/255.255.255.0)
 * 		- IP/BitMask (192.168.1.0/24)
 * ping		is 0 for not pinging et al 
 * 		if >0 then is the number of seconds timeout
 * verbose	is 0 for silence or >0 for verbosity
 */
int enumerate(char *dest,int ping,int verbose) {
    int			sfd;
    enum_target_t	*current,*new;
    u_int32_t		tnet,tnet2,l;
    char		*tp,*tp2;
    struct in_addr	n,m,mm;
    unsigned long int	t1;
    int			ping_retransmit;
    unsigned int	number_of_targets=0;

/* number of pings on multiple targets */
#define PING_ROUND	3		

    enum_free();
    enum_anchor=NULL;

    /* if the destination contains a / it is assumed to be a network/mask 
     * notation - eiter dotted mask or bits */
    if (!strchr(dest,'/')) {
	if (inet_aton(dest,&n)==0) {
	    struct hostent	*hd;
	    /* destination not IP address - try to resolve it */
            if ((hd=gethostbyname(dest))==NULL) {
		if (verbose)
		    fprintf(stderr,"Could not resolve destination host '%s'\n",
			    dest);
                return (-1);
            } else {
                bcopy(hd->h_addr,(char *)&(n),hd->h_length);
            }
	}
	if (ping) {
	    if (icmp_ping(&(n),ping,verbose)!=0) {
		if (verbose) 
		    fprintf(stderr,"single target not responding\n");
		return (-1);
	    }
	}

	/* this is just one */
	enum_anchor=smalloc(sizeof(enum_target_t));
	memcpy(&(enum_anchor->addr),&(n),sizeof(struct in_addr));
	number_of_targets=1;
	
    } else {
	/* assumption: these are mutiple targets */
	u_int32_t	q = 0xFFFFFFFF;
	int		lx1,lx2;

	/* multiple targets ....
	 * first, we have to figure out where ... */
	tp=smalloc(strlen(dest)+1);
	strcpy(tp,dest);
	tp2=strchr(tp,'/');
	tp2[0]='\0';
	tp2++;

	if (!strchr(tp2,'.')) {
	    lx1=atoi(tp2);
	    for (lx2=32;lx2>lx1;lx2--) q=q<<1; 
	    q=htonl(q);
	    memcpy(&(m.s_addr),&q,4);
	    if (verbose>2) printf("\tNetmask: %s\n",inet_ntoa(m));
	} else {
	    if (inet_aton(tp2,&m)==0) {
		if (verbose)
		    fprintf(stderr,"%s seems to be a stange mask\n",tp2);
		return (-1);
	    }
	}
	memcpy(&mm,&m,sizeof(m));

	/* network part must resulve as dotted */
	if (inet_aton(tp,&n)==0) {
	    fprintf(stderr,"%s seems to be a stange network address\n",tp);
	    return (-1);
	}

	/* calculate first and last address. */
	tnet = ntohl(  n.s_addr&m.s_addr  );
	tnet2= ntohl(  (m.s_addr^0xFFFFFFFF)|n.s_addr  );

	/* show addresses we are going to scan */
	if (verbose>1) {
	    n.s_addr=htonl(tnet);
	    m.s_addr=htonl(tnet2);
	    printf("Targeting from %s ",inet_ntoa(n));
	    printf("to %s\n",inet_ntoa(m));
	}

	/* add the records to the target list */
	t1=(unsigned long int)time(NULL);
	ping_retransmit=0;
	l=tnet;
	current=NULL;

	if (ping) {
	    /* from here on you need r00t perms */
	    if ((sfd=socket(AF_INET,SOCK_RAW,IPPROTO_ICMP))<0) {
		if (verbose) perror("socket()");
		return(-1);
	    }
	    if (makebcast(sfd)!=0) return(-1);
	    makenonblock(sfd);

	    while ( (unsigned long int)time(NULL)<(t1+ping) ) {
		struct sockaddr_in  	sin,fromaddr;
		u_char                      *tpacket;
		icmp_ping_t                 *pingh;
		int                         psize;
		u_int16_t                   pident;
		int                         rc,addrsize;

		psize=sizeof(icmp_ping_t);
		tpacket=(u_char *)smalloc(sizeof(icmp_ping_t)+64);
		pident=0xAF0D;
		/* make up the icmp header */
		pingh=(icmp_ping_t *)tpacket;
		pingh->icmp.type=ICMP_ECHO;
		pingh->icmp.code=0;
		pingh->echo.identifier=htons(pident);
		pingh->icmp.checksum=chksum((u_char *)pingh,psize);

		memset(&sin,0,sizeof(struct sockaddr_in));
		sin.sin_family=AF_INET;
		sin.sin_port=htons(0);

		if (ping_retransmit<PING_ROUND) l++;
		if (l>tnet2) { 
		    l=tnet; ping_retransmit++; 
		    if (verbose>1) printf("ping round is at %d\n",
			    ping_retransmit);
		}
		n.s_addr=htonl(l);
		usleep(10000);

		if (ping_retransmit<PING_ROUND) {
		    memcpy(&(sin.sin_addr),&n,sizeof(sin.sin_addr));
		    if (sendto(sfd,tpacket,psize,0,
			    (struct sockaddr *) &sin,
			    sizeof(struct sockaddr_in)) <0) {
			if (verbose) perror("sendto()");
			return(-1);
		    }
		}

		memset(&fromaddr,0,sizeof(struct sockaddr_in));
		addrsize=sizeof(struct sockaddr_in);
		memset(tpacket,0,psize);

		if ((rc=recvfrom(sfd,(u_char *)tpacket,psize,0,
			(struct sockaddr *)&fromaddr,
			&addrsize))>=0) {
		    pingh=(icmp_ping_t *)(tpacket+sizeof(iphdr_t));

		    if (pingh->icmp.type==ICMP_ECHOREPLY) {
			if (ntohs(pingh->echo.identifier)==pident) {
			    /* normal response */
			    if (verbose>1)
				printf("%s respond ... good\n",
				    inet_ntoa(fromaddr.sin_addr));

			    if ( /* same network check */
				(n.s_addr&mm.s_addr)==
				(fromaddr.sin_addr.s_addr&mm.s_addr)
				) {
				/* add the record of who respond */
				if (enum_known(&(fromaddr.sin_addr))==0) {
				    new=current;
				    current=smalloc(sizeof(enum_target_t));
				    memcpy(&(current->addr),
					    &(fromaddr.sin_addr),
					    sizeof(struct in_addr));
				    if (new==NULL) { new=current; } 
				    else { new->next=current; }
				    if (enum_anchor==NULL) { 
					enum_anchor=current; 
				    }
				    number_of_targets++;
				} /* enum_known check */
			    } /* same network */ else {
				if (verbose>1) 
				    printf("echo reply from system"
					    " outside range (%s)\n",
					    inet_ntoa(fromaddr.sin_addr));
			    } /* not same network */
			} /* ping ID */
		    } /* end of echo reply */
		} /* end of packet found */
	    } /* while time */
	} /* if ping */ else {

	    /* no network activity - just add them */
	    for (l=tnet;l<=tnet2;l++) {
		n.s_addr=htonl(l);
		new=current;
		current=smalloc(sizeof(enum_target_t));
		memcpy(&(current->addr),
			&(n),
			sizeof(struct in_addr));
		if (new==NULL) { new=current; } 
		else { new->next=current; }
		if (enum_anchor==NULL) { 
		    enum_anchor=current; 
		}
		number_of_targets++;
	    }
	}
	close(sfd);
    } /* if more then one */

    if (enum_anchor==NULL) return(-1);

    return number_of_targets;
}
