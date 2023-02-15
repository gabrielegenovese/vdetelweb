/*
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   telnet.c: telnet module
 *
 *   Copyright 2005,2007 Renzo Davoli University of Bologna - Italy
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, version 2 of the License.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *   $Id$
 *
 */

#include "vdetelweb.h"
#include <arpa/inet.h>
#include <arpa/telnet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ioth.h>
#include <libvdehist.h>
#include <linux/un.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define TELNET_TCP_PORT 23
#define TEMPTELNET_TCP_PORT 2323

void telnetdata(int fn, int fd, int vdefd)
{
  printf("ciaoo2\n");
  (void)fd;
  (void)vdefd;
  struct vdehiststat *vdehst = status[fn];
  if (vdehist_term_to_mgmt(vdehst) != 0)
  {
    int termfd = vdehist_gettermfd(vdehst);
    int mgmtfd = vdehist_getmgmtfd(vdehst);
    delpfd(pfdsearch(termfd));
    ioth_close(termfd);
    if (mgmtfd >= 0)
    {
      delpfd(mgmtfd);
      close(mgmtfd);
    }
    vdehist_free(vdehst);
  }
}

void telnet_vdedata(int fn, int fd, int vdefd)
{
  printf("ciaoo3\n");
  (void)fd;
  (void)vdefd;
  struct vdehiststat *vdehst = status[fn];
  vdehist_mgmt_to_term(vdehst);
}

char *telnet_logincmd(char *cmd, int len, struct vdehiststat *st)
{
  printf("ciaoo4\n");
  int histstatus = vdehist_getstatus(st);
  int termfd = vdehist_gettermfd(st);
  switch (histstatus)
  {
  case HIST_NOCMD:
    while (cmd[len - 1] == '\n')
      cmd[--len] = 0;
    if (strcmp(cmd, "admin") != 0)
      ioth_write(termfd, "login incorrect\r\n\r\nLogin: ", 26);
    else
    {
      ioth_write(termfd, "Password: ", 11);
      vdehist_setstatus(st, HIST_PASSWDFLAG);
    }
    break;
  case HIST_PASSWDFLAG:
  case HIST_PASSWDFLAG + 1:
  case HIST_PASSWDFLAG + 2:
    while (cmd[len - 1] == '\n')
      cmd[--len] = 0;
    if (!sha1passwdok(cmd))
    {
      histstatus++;
      vdehist_setstatus(st, histstatus);
      if (histstatus < (HIST_PASSWDFLAG + 3))
        ioth_write(termfd, "\r\nlogin incorrect\r\n\r\nPassword: ", 30);
      else
        return "logout";
    }
    else
    {
      int newfn;
      int flags;
      int mgmtfd;
      vdehist_setstatus(st, HIST_COMMAND);
      mgmtfd = openextravdem();
      if (mgmtfd >= 0)
      {
        vdehist_setmgmtfd(st, mgmtfd);
        flags = fcntl(mgmtfd, F_GETFL);
        flags |= O_NONBLOCK;
        fcntl(mgmtfd, F_SETFL, flags);
        newfn = addpfd(mgmtfd, telnet_vdedata);
        status[newfn] = st;
      }
      else
        return "logout";
      ioth_write(termfd, "\r\n", 2);
      ioth_write(termfd, prompt, strlen(prompt));
    }
  }
  return NULL;
}

void telnetaccept(int fn, int fd, int vdefd)
{
  printf("ciaoo1\n");
  (void)fn;
  (void)vdefd;
  struct sockaddr_in cli_addr;
  int newsockfd;
  unsigned int clilen;
  int newfn;

  clilen = sizeof(cli_addr);
  newsockfd = ioth_accept(fd, (struct sockaddr *)&cli_addr, &clilen);

  if (newsockfd < 0)
  {
    printlog(LOG_ERR, "telnet accept err: %s", strerror(errno));
    exit(-1);
  }

  newfn = addpfd(newsockfd, telnetdata);
  status[newfn] = vdehist_new(newsockfd, -1);
  ioth_write(newsockfd, banner, strlen(banner));
  ioth_write(newsockfd, "\r\nLogin: ", 9);
}

void telnet_init()
{
  int sockfd;
  struct sockaddr_in serv_addr;
  vdehist_termread = ioth_read;
  vdehist_termwrite = ioth_write;
  vdehist_logincmd = telnet_logincmd;
  sockfd = ioth_socket(AF_INET, SOCK_STREAM, 0);

  if (!sockfd)
  {
    printlog(LOG_ERR, "telnet socket err: %s", strerror(errno));
    exit(-1);
  }

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(TEMPTELNET_TCP_PORT); // se setto la 23 mi da problemi di permessi

  if (ioth_bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
  {
    printlog(LOG_ERR, "telnet bind err: %s", strerror(errno));
    exit(-1);
  }

  ioth_listen(sockfd, 5);

  addpfd(sockfd, telnetaccept);
}
