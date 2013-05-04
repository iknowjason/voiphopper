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
#include <sys/wait.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <setjmp.h>
#include <stdlib.h>
#include "pathnames.h"
#include "dhcpclient.h"

extern char		*ProgramName;
extern char		*IfNameExt;
extern char		*ConfigDir;
extern int		DebugFlag;
extern jmp_buf		env;
extern void		*(*currState)();
/*****************************************************************************/
void killPid(sig)
int sig;
{
  FILE *fp;
  pid_t pid;
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,ConfigDir,IfNameExt);
  fp=fopen(pidfile,"r");
  if ( fp == NULL ) goto ntrn;
  fscanf(fp,"%u",&pid);
  fclose(fp);
  if ( kill(pid,sig) )
    {
      unlink(pidfile);
ntrn: if ( sig == SIGALRM ) return;
      fprintf(stderr,"****  %s: not running\n",ProgramName);
      exit(1);
    }
  exit(0);
}
/*****************************************************************************/
void writePidFile(pid_t pid)
{
  FILE *fp;
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,ConfigDir,IfNameExt);
  fp=fopen(pidfile,"w");
  if ( fp == NULL )
    {
      syslog(LOG_ERR,"writePidFile: fopen: %m\n");
      exit(1);
    }
  fprintf(fp,"%u\n",pid);
  fclose (fp);
}
/*****************************************************************************/
void deletePidFile()
{
  char pidfile[64];
  snprintf(pidfile,sizeof(pidfile),PID_FILE_PATH,ConfigDir,IfNameExt);
  unlink(pidfile);
}
/*****************************************************************************/
void sigHandler(sig)
int sig;
{
  if( sig == SIGCHLD )
    {
      waitpid(-1,NULL,WNOHANG);
      return;
    }
  if ( sig == SIGALRM )
    {
      if ( currState == &dhcpBound ) {
	printf("currState == dhcpBound\n");
        siglongjmp(env,1); /* this timeout is T1 */
      } else
        {
          if ( currState == &dhcpRenew ) {
		printf("currState == dhcpRenew\n");
            siglongjmp(env,2); /* this timeout is T2 */
          } else
	    {
	      if ( currState == &dhcpRebind ){
		printf("currState == dhcpRebind\n");
	        siglongjmp(env,3);  /* this timeout is dhcpIpLeaseTime */
	      } else
		{
		  if ( currState == &dhcpReboot ){
			printf("currState == dhcpReboot\n");
			siglongjmp(env,4);  /* failed to acquire the same IP address */
		  } else
	            syslog(LOG_ERR,"timed out waiting for a valid DHCP server response\n");
		}
	    }
        }
    }
  else
    {
      if ( sig == SIGHUP ) 
	{
	  dhcpRelease();
	  /* allow time for final packets to be transmitted before shutting down     */
	  /* otherwise 2.0 drops unsent packets. fixme: find a better way than sleep */
	  sleep(1);
	}
	syslog(LOG_ERR,"terminating on signal %d\n",sig);
    }
  dhcpStop();
  deletePidFile();
  exit(sig);
}
/*****************************************************************************/
void signalSetup()
{
  int i;
  struct sigaction action;
  sigaction(SIGHUP,NULL,&action);
  action.sa_handler= &sigHandler;
  action.sa_flags = 0;
  for (i=1;i<16;i++) sigaction(i,&action,NULL);
  sigaction(SIGCHLD,&action,NULL);
}
