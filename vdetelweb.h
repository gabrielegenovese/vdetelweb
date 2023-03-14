#ifndef _VDETELWEB_H
#define _VDETELWEB_H
#define BUFSIZE 4096
#define true 1
#define false 0
#include <ioth.h>

typedef void (*voidfun)();

extern void *status[];
extern char *banner;
extern char *prompt;

int is_usr_correct(const char *usr);
int is_passwd_correct(const char *pw);
int addpfd(int fd, voidfun cb);
void delpfd(int fn);
int pfdsearch(int fd);
int open_extra_vde_mgmt();
void ssh_clean();
void ssh_init(struct ioth *iothstack, const char *path);
void telnet_init(struct ioth *iothstack);
void web_init(struct ioth *iothstack, int vdefd, char *cert, char *key);
void printlog(int priority, const char *format, ...);

#endif
