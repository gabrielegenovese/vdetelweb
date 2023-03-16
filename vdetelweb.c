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
 *   2023 migration from lwip to libioth by Gabriele Genovese
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
#include <getopt.h>
#include <linux/un.h>
#include <mhash.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <syslog.h>

int daemonize;
int ssh;
int telnet;
int web;
int vdefd;
char *conffile = NULL;
char *nodename = NULL;
char *https_cert = NULL;
char *ssh_cert = NULL;
char *key = NULL;
char *ip = NULL;
char *mgmt;
char *stack;
char *banner;
char *progname;
char *prompt;
int ifnet, logok;
static char *user;
static char *passwd;
static char *pidfile = NULL;
static char pidfile_path[_POSIX_PATH_MAX];
struct ioth *iothstack;

extern SSL *ssl;
extern SSL_CTX *ctx;
extern int is_ssl_enable;

#define UP 1
#define DOWN 0
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

/* print log string and exit if priority is LOG_ERR */
void printlog(int priority, const char *format, ...) {
  va_list arg;
  va_start(arg, format);

  if (logok)
    vsyslog(priority, format, arg);
  else {
    fprintf(stderr, "%s: ", progname);
    vfprintf(stderr, format, arg);
    fprintf(stderr, "\n");
  }
  va_end(arg);

  if (priority == LOG_ERR)
    exit(1);
}

static void cleanup() {
  if(ssh)
    ssh_clean();
  for (int i = 0; i < npfd; i++)
    ioth_close(pfd[npfd].fd);
  if (iothstack)
    ioth_delstack(iothstack);
  if ((pidfile != NULL) && unlink(pidfile_path) < 0)
    printlog(LOG_WARNING, "Couldn't remove pidfile '%s': %s", pidfile, strerror(errno));
  if (is_ssl_enable) {
    SSL_free(ssl);
    SSL_CTX_free(ctx);
  }
}

int is_usr_correct(const char *usr) {
  return (strcmp(user, usr) == 0);
}

int is_passwd_correct(const char *pw) {
  unsigned char out[mhash_get_block_size(MHASH_SHA1)];
  char outstr[mhash_get_block_size(MHASH_SHA1) * 2 + 1];
  unsigned int i;
  MHASH td;

  td = mhash_init(MHASH_SHA1);
  mhash(td, pw, strlen(pw));
  mhash_deinit(td, out);

  for (i = 0; i < mhash_get_block_size(MHASH_SHA1); i++) {
    outstr[2 * i] = hex[out[i] >> 4];
    outstr[2 * i + 1] = hex[out[i] & 0xf];
  }
  outstr[2 * i] = 0;

  return (memcmp(outstr, passwd, mhash_get_block_size(MHASH_SHA1)) == 0);
}

static void sig_handler(int sig) {
  cleanup();
  signal(sig, SIG_DFL);
  kill(getpid(), sig);
}

/* sets clean termination for SIGHUP, SIGINT and SIGTERM, and simply
 * ignores all the others signals which could cause termination. */
static void set_sighandlers() {
  struct {
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

  for (int i = 0; signals[i].sig != 0; i++)
    if (signal(signals[i].sig, signals[i].ignore ? SIG_IGN : sig_handler) == SIG_ERR)
      perror("Setting handler");
}

static void print_usage() {
  fprintf(stderr,
          "Usage:\t%s\t[-w] [-t] [-d] [-n nodename] [-f rcfile] [-p pidfile] "
          "[-k privatekeyfile] [-c certificatefile] mgmt_socket\n"
          "\t%s\t[--web] [--telnet] [--daemon] [--nodename nodename] [--rcfile rcfile]\n"
          "\t\t\t[--pidfile pidfile] [--key privatekeyfile] [--cert certificatefile] mgmt_socket\n",
          progname, progname);
  exit(-1);
}

void set_prompt(char *ctrl, char *nodename) {
  char buf[BUFSIZE];
  if (nodename == NULL) {
    struct utsname un;
    uname(&un);
    snprintf(buf, BUFSIZE, "VDE2@%s[%s]: ", un.nodename, ctrl);
  } else
    snprintf(buf, BUFSIZE, "VDE2@%s[%s]: ", nodename, ctrl);
  prompt = strdup(buf);
}

int open_extra_vde_mgmt() {
  struct sockaddr_un sun;
  char buf[BUFSIZE + 1];
  sun.sun_family = PF_UNIX;
  snprintf(sun.sun_path, UNIX_PATH_MAX, "%s", mgmt);
  int fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)(&sun), sizeof(sun)) < 0) {
    printlog(LOG_WARNING, "Error connecting to the mgmt socket '%s': %s", mgmt, strerror(errno));
    return -1;
  }
  if (read(fd, buf, BUFSIZE) <= 0) {
    printlog(LOG_WARNING, "banner %s", strerror(errno));
    return -1;
  }
  return fd;
}

int open_vde_mgmt(char *mgmt) {
  struct sockaddr_un sun;
  int fd, n;
  char buf[BUFSIZE + 1], *line2, *ctrl;
  sun.sun_family = PF_UNIX;
  snprintf(sun.sun_path, UNIX_PATH_MAX, "%s", mgmt);

  fd = socket(PF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)(&sun), sizeof(sun)) < 0)
    printlog(LOG_ERR, "Error connecting to the mgmt socket '%s': %s", mgmt, strerror(errno));

  if ((n = read(fd, buf, BUFSIZE)) <= 0)
    printlog(LOG_ERR, "Error reading banner from VDE switch: %s", strerror(errno));

  buf[n] = 0;
  if ((ctrl = rindex(buf, '\n')) != NULL)
    *ctrl = 0;
  banner = strdup(buf);

  if (write(fd, "ds/showinfo\n", 12) < 0)
    printlog(LOG_ERR, "Error writing ctl socket from VDE switch: %s", strerror(errno));
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
  set_prompt(ctrl, nodename);

  iothstack = ioth_newstack(stack, ctrl);
  printf("ioth %p\n", iothstack);

  if(iothstack == NULL)
    printlog(LOG_ERR, "ioth_newstack error: %s", strerror(errno));

  if ((ifnet = ioth_if_nametoindex(iothstack, "vde0")) < 0)
    printlog(LOG_ERR, "ioth_if_nametoindex error: %s", strerror(errno));

  if (ioth_linksetupdown(iothstack, ifnet, UP) < 0)
    printlog(LOG_ERR, "Error: link set up failed: %s", strerror(errno));

  return fd;
}

static void read_ip(char *full_ip, int af) {
  char *bit = rindex(full_ip, '/');
  if (bit == 0)
    printlog(LOG_ERR, "IP addresses must include the netmask i.e. addr/maskbits");

  int err, netmask = atoi(bit + 1);
  *bit = '\0';
  ip = strdup(full_ip);

  switch (af) {
  case PF_INET: {
    uint8_t ipv4[4];
    if ((err = inet_pton(af, full_ip, &ipv4) <= 0))
      printlog(LOG_ERR, "Convertion ipv4 error: %s", strerror(errno));

    if (ioth_ipaddr_add(iothstack, af, ipv4, netmask, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add ip: %s", strerror(errno));
  } break;
  case PF_INET6: {
    uint16_t ipv6[8];
    if ((err = inet_pton(af, full_ip, &ipv6) <= 0))
      printlog(LOG_ERR, "Convertion ipv6 error: %s", strerror(errno));

    if (ioth_ipaddr_add(iothstack, af, ipv6, netmask, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add ip: %s", strerror(errno));
  } break;
  default:
    printlog(LOG_ERR, "Unsupported Address Family: %s", full_ip);
  }
}

static void read_route_ip(char *full_ip, int af) {
  int err;
  switch (af) {
  case PF_INET: {
    uint8_t ipv4[4];
    if ((err = inet_pton(af, full_ip, &ipv4) <= 0))
      printlog(LOG_ERR, "Convertion route ipv4 error: %s", strerror(errno));

    if (ioth_iproute_add(iothstack, af, NULL, 0, ipv4, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add route ipv4: %s", strerror(errno));
  } break;
  case PF_INET6: {
    uint16_t ipv6[8];
    if ((err = inet_pton(af, full_ip, &ipv6) <= 0))
      printlog(LOG_ERR, "Convertion route ipv6 error: %s", strerror(errno));

    if (ioth_iproute_add(iothstack, af, NULL, 0, ipv6, ifnet) < 0)
      printlog(LOG_ERR, "Couldn't add ipv6: %s", strerror(errno));
  } break;
  default:
    printlog(LOG_ERR, "Unsupported Address Family: %s", full_ip);
  }
}

static void read_user(char *arg, int unused) {
  (void)unused;
  user = strdup(arg);
  if(user == NULL)
    printlog(LOG_ERR, "User must be set in the config file");
}

static void read_pass(char *arg, int unused) {
  (void)unused;
  passwd = strdup(arg);
  if(passwd == NULL)
    printlog(LOG_ERR, "Password must be set in the config file");
}

static void read_ssh_cert(char * arg, int unused) {
  (void)unused;
  ssh_cert = strdup(arg);
}

int read_conffile(char *path) {
  FILE *f;
  char buf[BUFSIZE], *s;
  int line = 0;

  struct cf {
    char *tag;
    void (*f)();
    int arg;
  } cft[] = {{"ip4", read_ip, PF_INET},
             {"ip6", read_ip, PF_INET6},
             {"ip", read_ip, PF_INET}, // ipv4 default
             {"defroute4", read_route_ip, PF_INET},
             {"defroute6", read_route_ip, PF_INET6},
             {"defroute", read_route_ip, PF_INET}, // ipv4 default
             {"user", read_user, 0},
             {"password", read_pass, 0},
             {"sshcert", read_ssh_cert, 0},
             {NULL, NULL, 0}};

  if (path == NULL)
    return -1;
  if ((f = fopen(path, "r")) == NULL)
    return -1;
  while (fgets(buf, BUFSIZE, f) != NULL) {
    line++;

    if ((s = rindex(buf, '\n')) != NULL)
      *s = 0;

    for (s = buf; *s == ' ' || *s == '\t'; s++)
      ;

    if (*s != '#' && *s != '\n' && *s != '\0') {
      struct cf *scf;
      for (scf = cft; scf->tag != NULL; scf++)
        if (strncmp(s, scf->tag, strlen(scf->tag)) == 0) {
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

int addpfd(int fd, voidfun cb) {
  if (npfd < MAXFD) {
    pfd[npfd].fd = fd;
    pfd[npfd].events = POLLIN | POLLHUP;
    pfd[npfd].revents = 0;
    fpfd[npfd] = cb;
    npfd++;
  }
  return npfd - 1;
}

void delpfd(int fn) {
  for (int i = fn; i < npfd - 1; i++) {
    pfd[i] = pfd[i + 1];
    fpfd[i] = fpfd[i + 1];
    status[i] = status[i + 1];
  }
  npfd--;
}

int pfdsearch(int fd) {
  int i;
  for (i = 0; i < npfd && pfd[i].fd != fd; i++)
    ;
  return i;
}

#if 0
int setfds(fd_set *rds, fd_set *exc) {
  int i, max = 0;
  FD_ZERO(rds);
  FD_ZERO(exc);
  for (i = 0; i < npfd; i++) {
    FD_SET(pfd[i].fd, rds);
    FD_SET(pfd[i].fd, exc);
    if (pfd[i].fd > max)
      max = pfd[i].fd;
  }
  return max + 1;
}
#endif

static void save_pidfile() {
  if (pidfile[0] != '/')
    strncat(pidfile_path, pidfile, _POSIX_PATH_MAX - strlen(pidfile_path));
  else
    strcpy(pidfile_path, pidfile);

  FILE *f;
  int fd = open(pidfile_path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

  if (fd == -1)
    printlog(LOG_ERR, "Error in pidfile creation: %s", strerror(errno));
  if ((f = fdopen(fd, "w")) == NULL)
    printlog(LOG_ERR, "Error in FILE* construction: %s", strerror(errno));

  if (fprintf(f, "%ld\n", (long int)getpid()) <= 0)
    printlog(LOG_ERR, "Error in writing pidfile");

  fclose(f);
}

/* this custom version of daemon(3) continue to receive stderr messages until
 * the end of the startup phase, the foreground process terminates when stderr
 * gets closed */
static int special_daemon() {
  int fd, n, errorpipe[2];
  char buf[256];
  ssize_t voidn;
  (void)voidn;

  if (pipe(errorpipe))
    return -1;

  switch (fork()) {
    case -1:
      return -1;
    case 0:
      break;
    default:
      close(errorpipe[1]);
      while ((n = read(errorpipe[0], buf, 128)) > 0)
        voidn = write(STDERR_FILENO, buf, n);
      _exit(0);
  }
  close(errorpipe[0]);

  if (setsid() == -1)
    return -1;

  voidn = chdir("/");

  if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
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
void manage_args(int argc, char *argv[]) {
  progname = argv[0];
  while (1) {
    int option_index = 0;
    static struct option long_options[] = {{"daemon", 0, 0, 'd'},
                                           {"stack", 1, 0, 'S'},
                                           {"mgmt", 1, 0, 'M'},
                                           {"telnet", 0, 0, 't'},
                                           {"ssh", 0, 0, 's'},
                                           {"web", 0, 0, 'w'},
                                           {"help", 0, 0, 'h'},
                                           {"rcfile", 1, 0, 'f'},
                                           {"cert", 1, 0, 'c'},
                                           {"key", 1, 0, 'k'},
                                           {"nodename", 1, 0, 'n'},
                                           {"pidfile", 1, 0, 'p'},
                                           {0, 0, 0, 0}};
    int c = getopt_long_only(argc, argv, "hdwtsMS:f:n:", long_options, &option_index);
    if (c == -1)
      break;

    switch (c) {
      case 'M':
        mgmt = strdup(optarg);
        break;
      case 'S':
        stack = strdup(optarg);
        break;
      case 'f':
        conffile = strdup(optarg);
        break;
      case 'n':
        nodename = strdup(optarg);
        break;
      case 't':
        telnet = 1;
        break;
      case 's':
        ssh = 1;
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
      case 'c':
        https_cert = strdup(optarg);
        break;
      case 'k':
        key = strdup(optarg);
        break;
      case 'h':
        print_usage(); // implies exit
        break;
    }
  }
  /* Check args */
  if (optind < argc && mgmt == NULL)
    mgmt = argv[optind];
  if (https_cert != NULL || key != NULL) {
    if (https_cert == NULL)
      printlog(LOG_ERR, "certificate option must be defined if a private key is specified");
    if (key == NULL)
      printlog(LOG_ERR, "private key option must be defined if a certificate is specified");
  }
  if (mgmt == NULL)
    printlog(LOG_ERR, "mgmt_socket not defined");
  if (telnet == 0 && web == 0 && ssh == 0)
    printlog(LOG_ERR, "at least one service option (-t -w -s) must be specified");

  atexit(cleanup);
  set_sighandlers();
}

void setup_daemonize() {
  /* saves current path in pidfile_path, because
   * otherwise with daemonize() we forget it */
  if (getcwd(pidfile_path, _POSIX_PATH_MAX - 1) == NULL)
    printlog(LOG_ERR, "getcwd: %s", strerror(errno));
  strcat(pidfile_path, "/");

  /* call daemon before starting the stack otherwise the stack
   * threads does not get inherited by the forked process */
  if (special_daemon())
    printlog(LOG_ERR, "daemon: %s", strerror(errno));
}

void handle(int vdefd) {
  if (telnet)
    printf("You can now connect with: telnet %s\n", ip);
  if (ssh)
    printf("You can now connect with: ssh %s@%s\n", user, ip);
  if (web)
    printf("You can now search in your browser http%c://%s\n", is_ssl_enable ? 's' : '\0', ip);
  while (1) {
    int m = poll(pfd, npfd, -1);
    for (int i = 0; i < npfd && m > 0; i++) {
      if (pfd[i].revents) {
        m--;
        fpfd[i](i, pfd[i].fd, vdefd);
      }
    }
  }
}

void check_and_read_conffile() {
  /* If rcfile is specified, try it and nothing else */
  if (conffile && read_conffile(conffile) < 0)
    printlog(LOG_ERR, "Error reading configuration file '%s': %s", conffile, strerror(errno));
  /* Else try default ones */
  else if (!conffile) {
    int rv = -1;
    char *homedir = getenv("HOME");
    if (homedir) {
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

void start_daemon() {
  int fd;
  if ((fd = open("/dev/null", O_RDWR)) >= 0) {
    close(STDERR_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    openlog(basename(progname), LOG_PID, 0);
    logok = 1;
  }
  printlog(LOG_INFO, "VDETELWEB started");
}

int main(int argc, char *argv[]) {
  manage_args(argc, argv);

  if (daemonize)
    setup_daemonize();

  vdefd = open_vde_mgmt(mgmt);

  check_and_read_conffile();

  /* once here, we're sure we're the true process which
   * will continue as a server: save PID file if needed */
  if (pidfile)
    save_pidfile();

  if (telnet)
    telnet_init(iothstack);
  if (web)
    web_init(iothstack, vdefd, https_cert, key);
  if (ssh)
    ssh_init(iothstack, ssh_cert);
  if (daemonize)
    start_daemon();

  handle(vdefd);
}
