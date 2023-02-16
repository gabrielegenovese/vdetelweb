#ifndef _VDETELWEB_H
#define _VDETELWEB_H
#define BUFSIZE 1024
typedef void (*voidfun)();

#include <ioth.h>

extern void *status[];

extern char *banner;
extern char *prompt;

int sha1passwdok(const char *pw);
int addpfd(int fd, voidfun cb);
void delpfd(int fn);
int pfdsearch(int fd);
int open_extra_vde_mgmt();
void telnet_init(struct ioth *iothstack);
void web_init(struct ioth *iothstack, int vdefd);

void printlog(int priority, const char *format, ...);

#endif
