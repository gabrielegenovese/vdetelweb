#ifndef _VDETELWEB_H
#define _VDETELWEB_H
#define BUFSIZE 2048
#define true 1
#define false 0
#include <ioth.h>

typedef void (*voidfun)();

extern void *status[];
extern char *banner;
extern char *prompt;

int is_user_correct(const char *ysr);
int is_password_correct(const char *pw);
int addpfd(int fd, voidfun cb);
void delpfd(int fn);
int pfdsearch(int fd);
int open_extra_vde_mgmt();
void my_ssh_clean();
void my_ssh_init(struct ioth *iothstack);
void telnet_init(struct ioth *iothstack);
void web_init(struct ioth *iothstack, int vdefd, char *cert, char *key);

void printlog(int priority, const char *format, ...);

#endif
