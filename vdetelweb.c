/*
 *   VDETELWEB: VDE telnet and WEB interface
 *
 *   vdetelweb.c: main
 *
 *   Copyright 2005,2008 Virtual Square Team University of Bologna - Italy
 *   2005 written by Renzo Davoli
 *   --pidfile/-p and cleanup management by Mattia Belletti (C) 2004
 *                            (copied from vde_switch code).
 *   2008 updated Renzo Davoli
 *   2008 sha1sum by Marco Dalla Via
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
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
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ioth.h>
#include <libgen.h>
#include <limits.h>
#include <linux/un.h>
#include <lwipv6.h>
#include <mhash.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

int daemonize;
int telnet;
int web;
char *mgmt;
char *banner;
char *progname;
char *prompt;
int ifnet, logok;
static char *passwd;
static char *pidfile = NULL;
static char pidfile_path[_POSIX_PATH_MAX];
struct ioth *iothstack;

#define MAXFD 16
#define HASH_SIZE 40
int npfd = 0;
struct pollfd pfd[MAXFD];
voidfun fpfd[MAXFD];
void *status[MAXFD];

/* This will be prefixed by getenv("HOME") */
#define USERCONFFILE "/.vde/vdetelwebrc"
#define ROOTCONFFILE "/etc/vde/vdetelwebrc"

static char hex[] = "0123456789abcdef";

void printlog(int priority, const char *format, ...)
{
  va_list arg;

  va_start(arg, format);

  if (logok)
    vsyslog(priority, format, arg);
  else
  {
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, format, arg);
    fprintf(stderr, "\n");
  }
  va_end(arg);

  if (priority == LOG_ERR)
    exit(-1);
}

static void cleanup()
{
  if (iothstack && ioth_delstack(iothstack) < 0)
    printlog(LOG_WARNING, "Couldn't free iothstack: %s", strerror(errno));
  if ((pidfile != NULL) && unlink(pidfile_path) < 0)
    printlog(LOG_WARNING, "Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
}

int sha1passwdok(const char *pw)
{
  unsigned char out[mhash_get_block_size(MHASH_SHA1)];
  char outstr[mhash_get_block_size(MHASH_SHA1) * 2 + 1];
  unsigned int i;
  MHASH td;

  td = mhash_init(MHASH_SHA1);
  mhash(td, pw, strlen(pw));
  mhash_deinit(td, out);

  for (i = 0; i < mhash_get_block_size(MHASH_SHA1); i++)
  {
    outstr[2 * i] = hex[out[i] >> 4];
    outstr[2 * i + 1] = hex[out[i] & 0xf];
  }
  outstr[2 * i] = 0;

  return (memcmp(outstr, passwd, mhash_get_block_size(MHASH_SHA1)) == 0);
}

static void sig_handler(int sig)
{
  cleanup();
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

static void setsighandlers()
{
  /* setting signal handlers.
   *    * sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
   *       * ignores all the others signals which could cause termination. */
  struct
  {
    int sig;
    const char *name;
    int ignore;
  } signals[] = {{SIGHUP, "SIGHUP", 0},
                 {SIGINT, "SIGINT", 0},
                 {SIGPIPE, "SIGPIPE", 1},
                 {SIGALRM, "SIGALRM", 1},
                 {SIGTERM, "SIGTERM", 0},
                 {SIGUSR1, "SIGUSR1", 1},
                 {SIGUSR2, "SIGUSR2", 1},
                 {SIGPOLL, "SIGPOLL", 1},
                 {SIGPROF, "SIGPROF", 1},
                 {SIGVTALRM, "SIGVTALRM", 1},
#ifdef SIGSTKFLT
                 {SIGSTKFLT, "SIGSTKFLT", 1},
#endif
                 {SIGIO, "SIGIO", 1},
                 {SIGPWR, "SIGPWR", 1},
#ifdef SIGUNUSED
                 {SIGUNUSED, "SIGUNUSED", 1},
#endif
                 {0, NULL, 0}};

  int i;
  for (i = 0; signals[i].sig != 0; i++)
    if (signal(signals[i].sig, signals[i].ignore ? SIG_IGN : sig_handler) == SIG_ERR)
      perror("Setting handler");
}

static void usage()
{
  fprintf(stderr,
          "Usage: %s [-w] [-t] [-d] [-n nodename] [-p pidfile] mgmt_socket\n"
          "       %s [--web] [--telnet] [--daemon] [--nodename nodename] "
          "[--pidfile pidfile] mgmt_socket\n",
          progname, progname);
  exit(-1);
}

void setprompt(char *ctrl, char *nodename)
{
  char buf[BUFSIZE];
  if (nodename == NULL)
  {
    struct utsname un;
    uname(&un);
    snprintf(buf, BUFSIZE, "VDE2@%s[%s]: ", un.nodename, ctrl);
  }
  else
    snprintf(buf, BUFSIZE, "VDE2@%s[%s]: ", nodename, ctrl);
  prompt = strdup(buf);
}

int openextravdem()
{
  struct sockaddr_un sun;
  int fd, n;
  char buf[BUFSIZE + 1];
  sun.sun_family = PF_UNIX;
  snprintf(sun.sun_path, UNIX_PATH_MAX, "%s", mgmt);
  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)(&sun), sizeof(sun)) < 0)
  {
    printlog(LOG_WARNING, "Error connecting to the management socket '%s': %s", mgmt, strerror(errno));
    return (-1);
  }
  if ((n = read(fd, buf, BUFSIZE)) <= 0)
  {
    printlog(LOG_WARNING, "banner %s", strerror(errno));
    return (-1);
  }
  return fd;
}

int open_vde_mgmt(char *mgmt, char *nodename)
{
  struct sockaddr_un sun;
  int fd, n;
  ssize_t voidn;
  (void)voidn;
  char buf[BUFSIZE + 1], *line2, *ctrl;
  sun.sun_family = PF_UNIX;

  snprintf(sun.sun_path, UNIX_PATH_MAX, "%s", mgmt);

  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)(&sun), sizeof(sun)) < 0)
    printlog(LOG_ERR, "Error connecting to the management socket '%s': %s", mgmt, strerror(errno));

  if ((n = read(fd, buf, BUFSIZE)) <= 0)
    printlog(LOG_ERR, "Error reading banner from VDE switch: %s", strerror(errno));

  buf[n] = 0;
  if ((ctrl = rindex(buf, '\n')) != NULL)
    *ctrl = 0;
  banner = strdup(buf);

  voidn = write(fd, "ds/showinfo\n", 12);
  if ((n = read(fd, buf, BUFSIZE)) <= 0)
    printlog(LOG_ERR, "Error reading ctl socket from VDE switch: %s", strerror(errno));

  buf[n] = 0;
  if ((line2 = index(buf, '\n')) == NULL)
    printlog(LOG_ERR, "Error parsing first line of ctl socket information");

  line2++;
  if (strncmp(line2, "ctl dir ", 8) != 0)
    printlog(LOG_ERR, "Error parsing ctl socket information");

  for (ctrl = line2 + 8; *ctrl != '\n' && ctrl < buf + n; ctrl++)
    ;

  *ctrl = 0;
  ctrl = line2 + 8;
  setprompt(ctrl, nodename);

  iothstack = ioth_newstack("vdestack", ctrl);
  ifnet = ioth_if_nametoindex(iothstack, "vde0");

  if (ioth_linksetupdown(iothstack, ifnet, 1) < 0)
    printlog(LOG_ERR, "Error: link set up failed");

  return fd;
}

static void read_ip(char *full_ip, int af)
{
  char *bit = rindex(full_ip, '/');

  if (bit == 0)
    printlog(LOG_ERR, "IP addresses must include the netmask i.e. addr/maskbits");

  int netmask = atoi(bit + 1);

  switch (af)
  {
  case PF_INET:
  {
    uint8_t ip[] = {0, 0, 0, 0};
    int i, j = 0, c = 0;
    char *num = malloc(sizeof(char) * 5);

    for (i = 0; i < 18; i++) // todo change 18 with const
    {
      if (full_ip[i] == '.' || full_ip[i] == '/')
      {
        num[c] = '\0';
        ip[j] = atoi(num);
        j++;
        c = 0;
      }
      else
      {
        num[c] = full_ip[i];
        c++;
      }
      if (full_ip[i] == '/')
        break;
    }

    free(num);
    if (ioth_ipaddr_add(iothstack, af, ip, netmask, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add ip");
  }
  break;
  case PF_INET6:
    // todo da fare
    break;
  default:
    printlog(LOG_ERR, "Unsupported Address Family: %s", full_ip);
  }
}

static void read_route_ip(char *full_ip, int af)
{
  switch (af)
  {
  case PF_INET:
  {
    uint8_t ip[] = {0, 0, 0, 0};
    int i, j = 0, c = 0;
    char *num = malloc(sizeof(char) * 5);

    for (i = 0; i < 18; i++) // todo change 18 with const
    {
      if (full_ip[i] == '.' || full_ip[i] == '\0')
      {
        num[c] = '\0';
        ip[j] = atoi(num);
        j++;
        c = 0;
      }
      else
      {
        num[c] = full_ip[i];
        c++;
      }
      if (full_ip[i] == '\0')
        break;
    }

    free(num);
    if (ioth_iproute_add(iothstack, af, NULL, 0, ip, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add route ip");
  }
  break;
  case PF_INET6:
    // todo da fare
    break;
  default:
    printlog(LOG_ERR, "Unsupported Address Family: %s", full_ip);
  }
}

static void read_pass(char *arg, int unused)
{
  (void)unused;
  passwd = strdup(arg);
}

struct cf
{
  char *tag;
  void (*f)();
  int arg;
} cft[] = {{"ip4", read_ip, PF_INET},
           {"ip6", read_ip, PF_INET6},
           {"ip", read_ip, 0},
           {"defroute4", read_route_ip, PF_INET},
           {"defroute6", read_route_ip, PF_INET6},
           {"defroute", read_route_ip, 0},
           {"password", read_pass, 0},
           {NULL, NULL, 0}};

int read_conffile(char *path)
{
  FILE *f;
  char buf[BUFSIZE], *s;
  int line = 0;

  if (path == NULL)
    return -1;
  if ((f = fopen(path, "r")) == NULL)
    return -1;
  while (fgets(buf, BUFSIZE, f) != NULL)
  {
    line++;

    if ((s = rindex(buf, '\n')) != NULL)
      *s = 0;

    for (s = buf; *s == ' ' || *s == '\t'; s++)
      ;

    if (*s != '#' && *s != '\n' && *s != '\0')
    {
      struct cf *scf;
      for (scf = cft; scf->tag != NULL; scf++)
        if (strncmp(s, scf->tag, strlen(scf->tag)) == 0)
        {
          s += strlen(scf->tag);
          for (; *s == ' ' || *s == '\t'; s++)
            ;
          if (*s == '=')
            s++;
          for (; *s == ' ' || *s == '\t'; s++)
            ;
          scf->f(s, scf->arg);
          break;
        }
      if (scf->tag == NULL)
        printlog(LOG_ERR, "Error parsing configuration file: line %d: %s", line, buf);
    }
  }
  return 0;
}

int addpfd(int fd, voidfun cb)
{
  if (npfd < MAXFD)
  {
    pfd[npfd].fd = fd;
    pfd[npfd].events = POLLIN | POLLHUP;
    pfd[npfd].revents = 0;
    fpfd[npfd] = cb;
    npfd++;
  }
  return npfd - 1;
}

void delpfd(int fn)
{
  int i = fn;
  for (i = fn; i < npfd - 1; i++)
  {
    pfd[i] = pfd[i + 1];
    fpfd[i] = fpfd[i + 1];
    status[i] = status[i + 1];
  }
  npfd--;
}

int pfdsearch(int fd)
{
  int i;
  for (i = 0; i < npfd && pfd[i].fd != fd; i++)
    ;
  return i;
}

#if 0
int setfds(fd_set *rds, fd_set *exc)
{
	int i,max=0;
	FD_ZERO(rds);
	FD_ZERO(exc);
	for (i=0;i<npfd;i++) {
		FD_SET(pfd[i].fd,rds);
		FD_SET(pfd[i].fd,exc);
		if (pfd[i].fd>max) max=pfd[i].fd;
	}
	return max+1;
}
#endif

static void save_pidfile(void)
{
  if (pidfile[0] != '/')
    strncat(pidfile_path, pidfile, _POSIX_PATH_MAX - strlen(pidfile_path));
  else
    strcpy(pidfile_path, pidfile);

  int fd = open(pidfile_path, O_WRONLY | O_CREAT | O_EXCL,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  FILE *f;

  if (fd == -1)
    printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));

  if ((f = fdopen(fd, "w")) == NULL)
    printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));

  if (fprintf(f, "%ld\n", (long int)getpid()) <= 0)
    printlog(LOG_ERR, "Error in writing pidfile");

  fclose(f);
}

/* this custom version of daemon(3) continue to receive stderr messages
 * until the end of the startup phase, the foreground process terminates
 * when stderr gets closed*/
static int special_daemon(void)
{
  int fd;
  int errorpipe[2];
  char buf[256];
  int n;
  ssize_t voidn;
  (void)voidn;

  if (pipe(errorpipe))
    return -1;

  switch (fork())
  {
  case -1:
    return (-1);
  case 0:
    break;
  default:
    close(errorpipe[1]);
    while ((n = read(errorpipe[0], buf, 128)) > 0)
    {
      voidn = write(STDERR_FILENO, buf, n);
    }
    _exit(0);
  }
  close(errorpipe[0]);

  if (setsid() == -1)
    return (-1);

  voidn = chdir("/");

  if ((fd = open("/dev/null", O_RDWR, 0)) != -1)
  {
    (void)dup2(fd, STDIN_FILENO);
    (void)dup2(fd, STDOUT_FILENO);
    (void)dup2(errorpipe[1], STDERR_FILENO);
    close(errorpipe[1]);
    if (fd > 2)
      (void)close(fd);
  }
  return 0;
}

/* Set option and exit if mngmt and telnet or web is not defined */
void manage_options(int argc, char *argv[], char **conffile, char **nodename)
{
  int c;
  while (1)
  {
    int option_index = 0;

    static struct option long_options[] = {
        {"daemon", 0, 0, 'd'},
        {"mgmt", 1, 0, 'M'},
        {"telnet", 0, 0, 't'},
        {"web", 0, 0, 'w'},
        {"help", 0, 0, 'h'},
        {"rcfile", 1, 0, 'f'},
        {"nodename", 1, 0, 'n'},
        {"pidfile", 1, 0, 'p'},
        {0, 0, 0, 0}};
    c = getopt_long_only(argc, argv, "hdwtM:f:n:", long_options, &option_index);
    if (c == -1)
      break;

    switch (c)
    {
    case 'M':
      mgmt = strdup(optarg);
      break;
    case 'f':
      *conffile = strdup(optarg);
      break;
    case 'n':
      *nodename = strdup(optarg);
      break;
    case 't':
      telnet = 1;
      break;
    case 'w':
      web = 1;
      break;
    case 'd':
      daemonize = 1;
      break;
    case 'p':
      pidfile = strdup(optarg);
      break;
    case 'h':
      usage(); // implies exit
      break;
    }
  }

  if (optind < argc && mgmt == NULL)
    mgmt = argv[optind];

  if (mgmt == NULL)
    printlog(LOG_ERR, "mgmt_socket not defined");
  if (telnet == 0 && web == 0)
    printlog(LOG_ERR, "at least one service option (-t -w) must be specified");
}

void setup_daemonize()
{
  /* saves current path in pidfile_path, because otherwise with daemonize() we forget it */
  if (getcwd(pidfile_path, _POSIX_PATH_MAX - 1) == NULL)
    printlog(LOG_ERR, "getcwd: %s", strerror(errno));
  strcat(pidfile_path, "/");

  /* call daemon before starting the stack otherwise the stack threads
   * does not get inherited by the forked process */
  if (special_daemon())
    printlog(LOG_ERR, "daemon: %s", strerror(errno));
}

void handle(int vdefd)
{
  while (1)
  {
    int i;
    int m = poll(pfd, npfd, -1);
    for (i = 0; i < npfd && m > 0; i++)
    {
      if (pfd[i].revents)
      {
        m--;
        fpfd[i](i, pfd[i].fd, vdefd);
      }
    }
  }
}

void read_config_file(char *conffile)
{
  /* If rcfile is specified, try it and nothing else */
  if (conffile && read_conffile(conffile) < 0)
    printlog(LOG_ERR, "Error reading configuration file '%s': %s", conffile, strerror(errno));
  /* Else try default ones */
  else if (!conffile)
  {
    int rv;
    char *homedir = getenv("HOME");
    if (homedir)
    {
      int len = strlen(homedir) + strlen(USERCONFFILE) + 1;
      conffile = malloc(len);
      snprintf(conffile, len, "%s%s", homedir, USERCONFFILE);
      if ((rv = read_conffile(conffile)) >= 0)
        free(conffile);
    }
    if (!homedir || rv < 0)
      rv = read_conffile(conffile = ROOTCONFFILE);

    if (rv < 0)
      printlog(LOG_ERR, "Error reading configuration file '%s': %s", conffile, strerror(errno));
  }
}

void start_daemon()
{
  int fd;
  if ((fd = open("/dev/null", O_RDWR)) >= 0)
  {
    close(STDERR_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    openlog(basename(progname), LOG_PID, 0);
    logok = 1;
  }
  printlog(LOG_INFO, "VDETELWEB started");
}

int main(int argc, char *argv[])
{
  int vdefd;
  char *conffile = NULL;
  char *nodename = NULL;
  progname = argv[0];

  manage_options(argc, argv, &conffile, &nodename);

  atexit(cleanup);
  setsighandlers();

  if (daemonize)
    setup_daemonize();

  vdefd = open_vde_mgmt(mgmt, nodename);

  read_config_file(conffile);

  /* once here, we're sure we're the true process which will continue as a
   * server: save PID file if needed */
  if (pidfile)
    save_pidfile();

  if (telnet)
    telnet_init(iothstack);
  if (web)
    web_init(iothstack, vdefd);

  if (daemonize)
    start_daemon();

  handle(vdefd);
}
