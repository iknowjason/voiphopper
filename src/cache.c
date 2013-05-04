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
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "pathnames.h"
#include "kversion.h"
#include "dhcpclient.h"
#include "dhcpcd.h"

extern	char		*ConfigDir;
extern	char		*IfNameExt;
extern	int		prev_ip_addr;
extern	dhcpInterface	DhcpIface;

char cache_file[128];

int readDhcpCache() {
  int i,o;
  snprintf(cache_file,sizeof(cache_file),DHCP_CACHE_FILE,ConfigDir,IfNameExt);
  i=open(cache_file,O_RDONLY);
  if ( i == -1 ) return -1;
  o=read(i,(char *)&DhcpIface,sizeof(dhcpInterface));
  close(i);
  if ( o != sizeof(dhcpInterface) ) return -1;
  if ( strncmp(DhcpIface.version,VERSION,sizeof(DhcpIface.version)) ) return -1;
  prev_ip_addr = DhcpIface.ciaddr;
  return 0;
}
/*****************************************************************************/
void deleteDhcpCache()
{
  snprintf(cache_file,sizeof(cache_file),DHCP_CACHE_FILE,ConfigDir,IfNameExt);
  unlink(cache_file);
}
