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

#ifndef PATHNAMES_H
#define PATHNAMES_H

#include <paths.h>
#include "dhcpcd.h"

#define PID_FILE_PATH		"%s/"PROGRAM_NAME"-%s.pid"
#define DHCP_CACHE_FILE		"%s/"PROGRAM_NAME"-%s.cache"
#define DHCP_HOSTINFO		"%s/"PROGRAM_NAME"-%s.info"
#define EXEC_ON_CHANGE		"%s/"PROGRAM_NAME".exe"

#ifdef EMBED
#define CONFIG_DIR		"/etc/config/dhcpc"
#define RESOLV_CONF		"/etc/config/resolv.conf"
#define NIS_CONF		"/etc/config/yp.conf"
#define NTP_CONF		"/etc/config/ntp.conf"
#else
#define CONFIG_DIR		"/etc/dhcpc"
#define RESOLV_CONF		"/etc/resolv.conf"
#define NIS_CONF		"/etc/yp.conf"
#define NTP_CONF		"/etc/ntp.conf"
#endif

#endif
