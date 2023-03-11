/*
 * VDETELWEB: VDE telnet and WEB interface
 *
 *   ssh.c: ssh module
 *
 *   Copyright 2005,2007 Renzo Davoli University of Bologna - Italy
 *   made by Gabriele Genovese heavily inspired by ssh example of wolfssh lib
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

#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_THREADING

#include "vdetelweb.h"
#include <ioth.h>
#include <syslog.h>
#include <wolfssh/ssh.h>
#include <wolfssh/test.h>

#define DEVPORT 2222
#define SSH_PORT 22

#define HIGHWATER_MARK_SZ 0x3FFF8000 /* 1GB - 32kB */
#define SSH_BUFFER_SZ 4096
#define LOADKEY_BUFFER_SZ 1200

static const char serverBanner[] = "VDETELWEB SSH Server\n";
int switch_mgmtfd;
int threadCount = 0;
WOLFSSH_CTX *ws_ctx = NULL;

typedef struct {
  WOLFSSH *ssh;
  SOCKET_T fd;
  word32 id;
} thread_ctx_t;

static byte byte_is_in(const byte *elem, const byte *buf) {
  const byte *cur = buf;
  while (*cur != '\0') {
    if (*elem == *cur)
      return *cur;
    cur++;
  }
  return 0;
}

static int print_prompt(thread_ctx_t *ctx) {
  word32 wxSz;
  char formatted_prompt[128];
  WSNPRINTF(formatted_prompt, sizeof(formatted_prompt), "\n%s", prompt);
  wxSz = (word32)strlen(formatted_prompt);
  return wolfSSH_stream_send(ctx->ssh, (byte *)formatted_prompt, wxSz);
}

static void ssh_showline(thread_ctx_t *ctx, byte *buf, int len, int indata) {
  if (indata)
    wolfSSH_stream_send(ctx->ssh, buf, len);
}

static int ssh_getanswer(voidfun f, void *arg, int vdefd) {
  char buf[BUFSIZE];
  char linebuf[BUFSIZE + 1];
  int n = 0, ib = 0, il = 0, indata = 0, eoa = 0;
  f(arg, "\n", 1, 1);
  do {
    n = read(vdefd, buf, BUFSIZE);
    if (n == 0)
      exit(0);
    for (ib = 0; ib < n; ib++) {
      linebuf[il++] = buf[ib];
      if (buf[ib] == '\n') {
        linebuf[il - 1] = '\r';
        linebuf[il++] = '\n';
        linebuf[il++] = 0;
        if (indata) {
          if (linebuf[0] == '.' && linebuf[1] == '\r')
            indata = 0;
          else
            f(arg, linebuf, il, indata);
        } else if (strncmp(linebuf, "0000", 4) == 0)
          indata = 1;
        else {
          if (linebuf[0] == '1' && linebuf[1] >= '0' && linebuf[1] <= '9' &&
              linebuf[2] >= '0' && linebuf[2] <= '9' && linebuf[3] >= '0' &&
              linebuf[3] <= '9') {
            f(arg, linebuf + 5, il - 5, 1);
            indata = 1;
            eoa = atoi(linebuf);
          }
        }
        il = 0;
      }
    }
  } while (!eoa);
  return (eoa);
}

void close_sshclient(thread_ctx_t *ctx) {
  wolfSSH_stream_exit(ctx->ssh, 0);
  WCLOSESOCKET(ctx->fd);
  wolfSSH_free(ctx->ssh);
  free(ctx);
}

static THREAD_RETURN WOLFSSH_THREAD server_worker(void *vArgs) {
  thread_ctx_t *threadCtx = (thread_ctx_t *)vArgs;

  if (wolfSSH_accept(threadCtx->ssh) == WS_SUCCESS) {

    byte *buf = NULL;
    byte *tmpBuf;
    char cmd[100];
    int bufSz, backlogSz = 0, rxSz, txSz, stop = 0, txSum;
    int letter_count = 0;

    if ((switch_mgmtfd = open_extra_vde_mgmt()) < 0)
      stop = 1;
    else
      print_prompt(threadCtx);

    do {
      bufSz = SSH_BUFFER_SZ + backlogSz;
      tmpBuf = (byte *)realloc(buf, bufSz);
      if (tmpBuf == NULL)
        stop = 1;
      else
        buf = tmpBuf;

      if (!stop) {
        do {
          rxSz = wolfSSH_stream_read(threadCtx->ssh, buf, SSH_BUFFER_SZ);
          if (rxSz <= 0)
            rxSz = wolfSSH_get_error(threadCtx->ssh);
        } while (rxSz == WS_WANT_READ || rxSz == WS_WANT_WRITE);

        if (rxSz > 0) {
          backlogSz += rxSz;
          txSum = 0;
          txSz = 0;

          while (backlogSz != txSum && txSz >= 0 && !stop) {

            int do_write = true;
            const byte matches[] = {0x03, 0x0D, 0x7F, 0x1B, 0x00};

            byte c = byte_is_in(buf + txSum, matches);
            switch (c) {
            case 0x03: // ctrl+C : close
              stop = 1;
              break;
            case 0x0D: // enter : send command
              if (letter_count > 0) {
                cmd[letter_count] = '\0';

                wolfSSH_stream_send(threadCtx->ssh, (byte *)"\n", 1);
                ssize_t voidn;
                (void)voidn;
                for (int i = 0; i < letter_count + (int)strlen(prompt); i++) {
                  *(buf + txSum) = 0x08;
                  wolfSSH_stream_send(threadCtx->ssh, buf + txSum, backlogSz - txSum);
                }
                voidn = write(switch_mgmtfd, cmd, strlen(cmd));         // send command
                ssh_getanswer(ssh_showline, threadCtx, switch_mgmtfd);  // get output
              } else {
                // get back cursor
                for (int i = 0; i < (int)strlen(prompt); i++) {
                  *(buf + txSum) = 0x08;
                  wolfSSH_stream_send(threadCtx->ssh, buf + txSum, backlogSz - txSum);
                }
              }
              print_prompt(threadCtx);
              wolfSSH_stream_send(threadCtx->ssh, (byte *)" ", 1);
              letter_count = 0;
              break;
            case 0x7F: // backspace : del command
              if (letter_count > 0) {
                *(buf + txSum) = 0x08;
                wolfSSH_stream_send(threadCtx->ssh, buf + txSum, backlogSz - txSum);
                *(buf + txSum) = 0x20;
                wolfSSH_stream_send(threadCtx->ssh, buf + txSum, backlogSz - txSum);
                *(buf + txSum) = 0x08;
                letter_count--;
              } else {
                do_write = false;
                txSum++;
              }
              break;
            case 0x1B: // escape char - arrow pressed
              // skip
              do_write = false;
              txSz = 3;
              txSum += txSz;
              break;
            default:
              cmd[letter_count] = *(buf + txSz); // add char to cmd
              ++letter_count;
            }

            if (do_write) {
              txSz = wolfSSH_stream_send(threadCtx->ssh, buf + txSum, backlogSz - txSum);
              txSum += txSz;
            }
          }

          if (txSum < backlogSz)
            memmove(buf, buf + txSum, backlogSz - txSum);
          backlogSz -= txSum;
        } else
          stop = 1;
      }
    } while (!stop);

    free(buf);
  } else
    printlog(LOG_WARNING, "Couldn't connect to client: %s", strerror(errno));

  close_sshclient(threadCtx);
  return 0;
}

static int load_file(const char *fileName, byte *buf, word32 bufSz) {
  FILE *file;
  word32 fileSz;
  word32 readSz;

  if (fileName == NULL)
    return 0;

  if (WFOPEN(&file, fileName, "rb") != 0)
    return 0;
  fseek(file, 0, SEEK_END);
  fileSz = (word32)ftell(file);
  rewind(file);

  if (fileSz > bufSz) {
    fclose(file);
    return 0;
  }

  readSz = (word32)fread(buf, 1, fileSz, file);
  if (readSz < fileSz) {
    fclose(file);
    return 0;
  }

  fclose(file);
  return fileSz;
}

static int wsUserAuth(byte authType, WS_UserAuthData *authData, void *unused) {
  (void)unused;
  if (authType != WOLFSSH_USERAUTH_PASSWORD)
    return WOLFSSH_USERAUTH_FAILURE;

  if (authData->type != WOLFSSH_USERAUTH_PASSWORD)
    return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;

  if (is_usr_correct((char *)authData->username)) {
    char *pwd = strdup((char *)authData->sf.password.password);
    pwd[authData->sf.password.passwordSz] = '\0';
    if (is_passwd_correct(pwd))
      return WOLFSSH_USERAUTH_SUCCESS;
    else
      return WOLFSSH_USERAUTH_INVALID_PASSWORD;
  } else
    return WOLFSSH_USERAUTH_INVALID_USER;
}

void init_wolfssh(const char *path) {
  if(path == NULL)
    printlog(LOG_ERR, "SSH path not set in config file");

  byte buf[LOADKEY_BUFFER_SZ];
  word32 bufSz;

  if (wolfSSH_Init() != WS_SUCCESS)
    printlog(LOG_ERR, "Couldn't initialize wolfSSH: %s", strerror(errno));

  ws_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
  if (ws_ctx == NULL)
    printlog(LOG_ERR, "Couldn't allocate SSH CTX data: %s", strerror(errno));

  wolfSSH_SetUserAuth(ws_ctx, wsUserAuth);
  wolfSSH_CTX_SetBanner(ws_ctx, serverBanner);

  bufSz = load_file(path, buf, LOADKEY_BUFFER_SZ); // load key
  if (bufSz == 0)
    printlog(LOG_ERR, "Couldn't load key: %s", strerror(errno));
  if (wolfSSH_CTX_UsePrivateKey_buffer(ws_ctx, buf, bufSz,
                                       WOLFSSH_FORMAT_ASN1) < 0)
    printlog(LOG_ERR, "Couldn't use key buffer: %s", strerror(errno));
}

void ssh_clean() {
  if (wolfSSH_Cleanup() != WS_SUCCESS)
    printlog(LOG_WARNING, "Couldn't clean up wolfSSH: %s", strerror(errno));
}

void ssh_accept(int fn, int fd, int vdefd) {
  (void)fn;
  (void)vdefd;
  WS_SOCKET_T cli_fd;
  struct sockaddr_in cli_addr;
  socklen_t cli_addrsz = sizeof(cli_addr);
  THREAD_TYPE thread;
  WOLFSSH *ssh;
  thread_ctx_t *threadCtx;

  threadCtx = (thread_ctx_t *)malloc(sizeof(thread_ctx_t));
  if (threadCtx == NULL)
    printlog(LOG_ERR, "Couldn't alloc thread ctx data: %s", strerror(errno));

  ssh = wolfSSH_new(ws_ctx);
  if (ssh == NULL)
    printlog(LOG_ERR, "Couldn't alloc SSH data: %s", strerror(errno));

  /* Use the session object for its own highwater callback ctx */
  wolfSSH_SetHighwaterCtx(ssh, (void *)ssh);
  wolfSSH_SetHighwater(ssh, HIGHWATER_MARK_SZ);

  if ((cli_fd = ioth_accept(fd, (struct sockaddr *)&cli_addr, &cli_addrsz)) < 0)
    printlog(LOG_ERR, "telnet accept err: %s", strerror(errno));

  wolfSSH_set_fd(ssh, cli_fd);

  threadCtx->ssh = ssh;
  threadCtx->fd = cli_fd;
  threadCtx->id = threadCount++;

  ThreadStart(server_worker, threadCtx, &thread);
  ThreadDetach(thread);
}

void ssh_init(struct ioth *iothstack, const char *path) {
  int sockfd;
  struct sockaddr_in serv_addr;
  init_wolfssh(path);

  if ((sockfd = ioth_msocket(iothstack, AF_INET, SOCK_STREAM, 0)) == 0)
    printlog(LOG_ERR, "telnet socket err: %s", strerror(errno));

  bzero((char *)&serv_addr, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(DEVPORT); // todo: change the port in prod/dev

  if (ioth_bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    printlog(LOG_ERR, "ssh bind err: %s", strerror(errno));

  ioth_listen(sockfd, 5);
  addpfd(sockfd, ssh_accept);
}
