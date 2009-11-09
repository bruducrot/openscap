#pragma once
#ifndef SEAP_H
#define SEAP_H

#ifndef SEAP_MSGID_BITS
# define SEAP_MSGID_BITS 32
#endif

#include <stdint.h>
#include <seap-debug.h>
#include <sexp.h>
#include <seap-types.h>
#include <seap-message.h>
#include <seap-command.h> 
#include <seap-error.h>

SEAP_CTX_t *SEAP_CTX_new  (void);
void        SEAP_CTX_init (SEAP_CTX_t *ctx);
void        SEAP_CTX_free (SEAP_CTX_t *ctx);

int     SEAP_connect (SEAP_CTX_t *ctx, const char *uri, uint32_t flags);
int     SEAP_listen (SEAP_CTX_t *ctx, int sd, uint32_t maxcli);
int     SEAP_accept (SEAP_CTX_t *ctx, int sd);

int     SEAP_open  (SEAP_CTX_t *ctx, const char *path, uint32_t flags);
SEXP_t *SEAP_read  (SEAP_CTX_t *ctx, int sd);
int     SEAP_write (SEAP_CTX_t *ctx, int sd, SEXP_t *sexp);
int     SEAP_close (SEAP_CTX_t *ctx, int sd);

int SEAP_openfd (SEAP_CTX_t *ctx, int fd, uint32_t flags);
int SEAP_openfd2 (SEAP_CTX_t *ctx, int ifd, int ofd, uint32_t flags);

#if 0
# include <stdio.h>
int SEAP_openfp (SEAP_CTX_t *ctx, FILE *fp, uint32_t flags);
#endif /* 0 */

SEAP_msg_t *SEAP_msg_new (void);
void        SEAP_msg_free (SEAP_msg_t *msg);
int         SEAP_msg_set (SEAP_msg_t *msg, SEXP_t *sexp);
SEXP_t     *SEAP_msg_get (SEAP_msg_t *msg);

int     SEAP_msgattr_set (SEAP_msg_t *msg, const char *attr, SEXP_t *value);
SEXP_t *SEAP_msgattr_get (SEAP_msg_t *msg, const char *name);

int SEAP_recvsexp (SEAP_CTX_t *ctx, int sd, SEXP_t **sexp);
int SEAP_recvmsg  (SEAP_CTX_t *ctx, int sd, SEAP_msg_t **seap_msg);

int SEAP_sendsexp (SEAP_CTX_t *ctx, int sd, SEXP_t *sexp);
int SEAP_sendmsg  (SEAP_CTX_t *ctx, int sd, SEAP_msg_t *seap_msg);

int SEAP_reply (SEAP_CTX_t *ctx, int sd, SEAP_msg_t *rep_msg, SEAP_msg_t *req_msg);

int SEAP_senderr (SEAP_CTX_t *ctx, int sd, SEAP_err_t *err);
int SEAP_recverr (SEAP_CTX_t *ctx, int sd, SEAP_err_t **err);
int SEAP_recverr_byid (SEAP_CTX_t *ctx, int sd, SEAP_err_t **err, SEAP_msgid_t id);

int SEAP_replyerr (SEAP_CTX_t *ctx, int sd, SEAP_msg_t *rep_msg, uint32_t e);

#endif /* SEAP_H */
