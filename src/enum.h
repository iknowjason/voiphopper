/* ICMP enumeration for libpackets 
 * 
 * $Id: enum.h,v 1.3 2001/07/03 20:00:10 fx Exp $
 * */
#ifndef _ENUM_H_
#define _ENUM_H_

#include <netinet/in.h>

typedef struct {
    struct in_addr	addr;
    void		*next;
} enum_target_t;

extern enum_target_t	*enum_anchor;

int	enumerate(char *dest,int ping,int verbose);
int	enum_known(struct in_addr *addr);
int	enum_print(void);
void	enum_free(void);

#endif _ENUM_H_
