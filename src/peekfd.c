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

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
/*****************************************************************************/
int peekfd(s,tv_usec)
int s;
time_t tv_usec;
{
  fd_set fs;
  struct timeval tv;

  FD_ZERO(&fs);
  FD_SET(s,&fs);
  tv.tv_sec=tv_usec/1000000;
  tv.tv_usec=tv_usec%1000000;

  if ( select(s+1,&fs,NULL,NULL,&tv) == -1 ) return -1;
  if ( FD_ISSET(s,&fs) ) return 0;
  return 1;
}
