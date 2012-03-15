/**
 *  ACS ACR-120S Smartcard Reader Library
 *  Copyright (C) 2009 - 2012, Ardhan Madras <ajhwb@knac.com>
 *
 *  Last modification: 03/14/2012
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  ACR-120S BINARY PROTOCOL:
 *  +-----------+-----------+-------------+----------+---------+---------+
 *  |    STX    |    SID    | DATA LENGTH | CMD/DATA |   BCC   |   ETX   |
 *  |   1 byte  |   1 byte  |   1 byte    |  n bytes | 1 byte  |  1 byte |
 *  +-----------+-----------+-------------+----------+---------+---------+
 *
 *  BCC is calculating by XOR-ing each byte from SID to CMD/DATA
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "acr120.h"

#define STX 0x2
#define ETX 0x3
#define REPLY_TIMEOUT   100000
#define USEC_PER_SEC    1000000

struct _acr120_ctx {
    struct termios current_opt;  /* Current terminal option */
    struct termios old_opt;      /* Old terminal option (to restore on close) */
    int fd;                      /* The file descriptor */
    int io_timeo;                /* IO timeout (read/write) in mileseconds */
    int error;                   /* Error code */
    unsigned char proto_mode;    /* Protocol mode */
    unsigned char station_id;    /* Station ID */
};

typedef struct _acr120_ctx acr120_ctx;

static void dec2nibble(unsigned int, unsigned char*);
static void nibble2dec(unsigned int*, unsigned char*);
static int check_bin_error(const unsigned char*, size_t);
static int check_ascii_error(const unsigned char*, size_t);
static int acr120_timeout(acr120_ctx*, int);

static const char *acr120_error[] = {
    "Success",
    "Open device failure",
    "Close device failure",
    "Device setting failure",
    "Write device failure",
    "Read device failure",
    "Select device failure",
    "Operation timeout",
    "No TAG",
    "No value block",
    "Login fail, key wrong",
    "Invalid key format (stored key)",
    "Read failure",
    "Unable to read after write",
    "Read after write error",
    "Write failure",
    "Unable to read after increment",
    "Increment failure",
    "Unable to read after decrement",
    "Decrement failure",
    "Empty value decrement",
    "Unable to read after copy",
    "Copy failure",
    "Data error"
};

#define check_error(ctx, ans, nr) \
do { \
if (ctx->proto_mode) { \
    if (check_bin_error(ans, (nr))) { \
        ctx->error = 23; \
        return ACR120_ERROR; \
    } \
} else { \
    if (check_ascii_error(ans, (nr))) { \
        ctx->error = 23; \
        return ACR120_ERROR; \
    } \
} \
} while (0);

static void dec2nibble(unsigned int value, unsigned char *nibble)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    nibble[3] = value & 0xff;
    nibble[2] = value >> 8 & 0xff;
    nibble[1] = value >> 16 & 0xff;
    nibble[0] = value >> 24 & 0xff;
#else
    nibble[0] = value & 0xff;
    nibble[1] = value >> 8 & 0xff;
    nibble[2] = value >> 16 & 0xff;
    nibble[3] = value >> 24 & 0xff;
#endif
}

static void nibble2dec(unsigned int *val, unsigned char *nibble)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    *val = nibble[3] | (nibble[2] << 8) | (nibble[1] << 16) | (nibble[0] << 24);
#else
    *val = nibble[0] | (nibble[1] << 8) | (nibble[2] << 16) | (nibble[3] << 24);
#endif
}

static int check_bin_error(const unsigned char *ans, size_t len)
{
    unsigned char check = 0;
    int i, nc = len - 2 * sizeof(unsigned char);

    for (i = 1; i < nc; i++)
        check ^= ans[i];
    return (check == ans[nc]) ? 0 : 1;
}

static int check_ascii_error(const unsigned char *ans, size_t len)
{
    return (ans[len - 2] == 0xd && ans[len -1] == 0xa) ? 0 : 1;
}

int acr120_errno(acr120_ctx *ctx)
{
    return ctx->error;
}

const char* acr120_strerror(acr120_ctx *ctx)
{
    return acr120_error[ctx->error];
}

int acr120_change_speed(acr120_ctx *ctx, speed_t speed)
{
    int ret;
    struct termios opt;

    ret = tcgetattr(ctx->fd, &opt);
    if (ret == -1) {
        ctx->error = 1;
        return ACR120_ERROR;
    }
    cfsetispeed(&opt, speed);
    cfsetospeed(&opt, speed);
    ret = tcsetattr(ctx->fd, TCSANOW, &opt);
    if (ret == -1) {
        ctx->error = 3;
        return ACR120_ERROR;
    }
    ctx->error = 0;
    ctx->current_opt = opt;
    return ACR120_SUCCESS;
}

acr120_ctx *acr120_init(const char *dev, int station_id, speed_t speed, int timeout)
{
    int ret;
    unsigned char cmd[8], ans[6], val;
    size_t bytes = 0;
    struct termios old_opt, current_opt;
    acr120_ctx *ctx;

    ctx = (acr120_ctx*) malloc(sizeof(acr120_ctx));
    if (!ctx)
        return NULL;

    ctx->fd = open(dev, O_RDWR | O_NOCTTY);
    if (ctx->fd == -1) {
        ctx->error = 1;
        return ctx;
    }

    ret = tcgetattr(ctx->fd, &old_opt);
    if (ret == -1) {
        ctx->error = 3;
        return ctx;
    }

    /* 
     * Set to 8N1, save previous setting to restore on close.
     */
    memcpy(&current_opt, &old_opt, sizeof(struct termios));

    cfsetispeed(&current_opt, speed);
    cfsetospeed(&current_opt, speed);

    current_opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    current_opt.c_iflag &= ~(INLCR | ICRNL | IXON | IXOFF);
    current_opt.c_oflag &= ~(ONLCR | OCRNL);
    current_opt.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    current_opt.c_cflag |= CS8;
    ret = tcsetattr(ctx->fd, TCSANOW, &current_opt);
    if (ret == -1) {
        close(ctx->fd);
        ctx->fd = -1;
        ctx->error = 3;
        return ctx;
    }

    /*
     * Read protocol register to obtain protocol mode, let's try in 
     * ASCII mode first, if this fails goto BINARY mode.
     * Edane - Paraelit (Zep 170 Volts)
     */
    snprintf((char *) cmd, 5, "re%.2x", ACR120_REGISTER_PROTOCOL);
    while (bytes < 4) {
        ret = write(ctx->fd, cmd + bytes, 4 - bytes);
        if (ret <= 0) {
            ctx->error = 4;
reset:
            tcsetattr(ctx->fd, TCSANOW, &old_opt);
            close(ctx->fd);
            ctx->fd = -1;
            return ctx;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < 4) {
        ret = acr120_timeout(ctx, timeout);
        if (ret == ACR120_ERROR) {
            if (ctx->error != 7)
                goto reset;
            goto bin;
        }

        ret = read(ctx->fd, ans + bytes, 4 - bytes);
        if (ret <= 0) {
            ctx->error = 5;
            goto reset;
        }
        bytes += ret;
    }

    if (check_ascii_error(ans, 4)) {
        ctx->error = 23;
        goto reset;
    }

    ans[2] = 0;
    sscanf((char*) ans, "%x", (unsigned int*) &val);
    goto done;

    /* 
     * The ASCII mode fails, now probe in BINARY mode.
     */
bin:

    cmd[0] = STX;
    cmd[1] = station_id;
    cmd[2] = 0x3;
    cmd[3] = 'r';
    cmd[4] = 'e';
    cmd[5] = ACR120_REGISTER_PROTOCOL;
    cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
    cmd[7] = ETX;

    bytes = 0;
    while (bytes < sizeof(cmd)) {
        ret = write(ctx->fd, cmd + bytes, sizeof(cmd) - bytes);
        if (ret <= 0) {
            ctx->error = 4;
            goto reset;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < sizeof(ans)) {
        ret = acr120_timeout(ctx, timeout);
        if (ret == ACR120_ERROR)
            goto reset;
        ret = read(ctx->fd, ans + bytes, sizeof(ans) - bytes);
        if (ret <= 0) {
            ctx->error = 5;
            goto reset;
        }
        bytes += ret;

        /*
         * Unfortunately there are no error code reply for reading 
         * register value in binary mode, only check here for fun. 
         **/
        if (bytes > 3 && ans[2] == 1) {
            switch (ans[3]) {
                case 'N':
                    ctx->error = 8;
                    goto reset;
                case 'I':
                    ctx->error = 9;
                    goto reset;
                case 'F':
                    ctx->error = 12;
                    goto reset;
            }
        }
    }

    if (check_bin_error(ans, sizeof(ans))) {
        ctx->error = 23;
        goto reset;
    }
    val = ans[3];

done:
    /* Set protocol mode */
    ctx->proto_mode = val >> 1 & 0x1;
    ctx->error = 0;
    ctx->current_opt = current_opt;
    ctx->old_opt = old_opt;
    ctx->station_id = station_id;
    ctx->io_timeo = timeout;
    return ctx;
}

void acr120_free(acr120_ctx *ctx)
{
    /* Restore previous setting */
    if (ctx->fd != -1) {
        tcsetattr(ctx->fd, TCSANOW, &ctx->old_opt);
        close(ctx->fd);
    }
    free(ctx);
}

/*
 * Used for read operation timeout, REPLY_TIEMOUT time
 * (in miliseconds) should be a comfortable value.
 */
static int acr120_timeout(acr120_ctx *ctx, int timeout)
{
    int ret;
    fd_set rset;
    struct timeval val;

    FD_ZERO(&rset);
    FD_SET(ctx->fd, &rset);

    if (timeout < 0) val.tv_usec = REPLY_TIMEOUT;
    else if (timeout == 0) val.tv_usec = 0;
    else val.tv_usec = timeout * 1000;
    val.tv_sec = 0;

    while (val.tv_usec >= USEC_PER_SEC) {
        val.tv_sec++;
        val.tv_usec -= USEC_PER_SEC;
    }

    ret = select(ctx->fd + 1, &rset, NULL, NULL, &val);
    if (ret == 0) {
        ctx->error = 7;
        return ACR120_ERROR;
    }
    if (ret == -1) {
        ctx->error = 6;
        return ACR120_ERROR;
    }
    if (FD_ISSET(ctx->fd, &rset)) {
        ctx->error = 0;
        return ACR120_SUCCESS;
    }
    /* Should never reach here */
    ctx->error = 6;
    return ACR120_ERROR;
}

int acr120_reset(acr120_ctx *ctx, int need_reply)
{
    int ret;
    unsigned char cmd[6], ans[12];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x1;
        cmd[3] = 'x';
        cmd[4] = cmd[1] ^ cmd[2] ^ cmd[3];
        cmd[5] = ETX;
        nw = sizeof(cmd);
        nr = sizeof(ans);
    } else {
        cmd[0] = 'x';
        nw = 1;
        nr = 0;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    /*
     * There are no reply on BINARY mode, and its reply data
     * is not in protocol format, it is actually a string 
     * outputed as 'ACR120 24S', bypass the binary error check.
     */
    bytes = 0;
    while (need_reply && ctx->proto_mode && bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_get_id(acr120_ctx *ctx, unsigned char *id)
{
    int ret;
    unsigned char cmd[6], ans[6];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = 0xff;
        cmd[2] = 0x1;
        cmd[3] = 'g';
        cmd[4] = cmd[1] ^ cmd[2] ^ cmd[3];
        cmd[5] = ETX;
        nw = sizeof(cmd);
        nr = sizeof(ans);
    } else {
        cmd[0] = 'g';
        nw = 1;
        nr = 3;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    check_error(ctx, ans, nr);

    if (id)
        *id = ctx->proto_mode ? ans[3] : ans[0];

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_select(acr120_ctx *ctx, unsigned int *uid)
{
    int ret;
    unsigned char cmd[6], ans[10], uids[4];
    size_t bytes = 0, nr, nw;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x1;
        cmd[3] = 's';
        cmd[4] = cmd[1] ^ cmd[2] ^ cmd[3];
        cmd[5] = ETX;
        nw = sizeof(cmd);
        nr = 9;
    } else {
        cmd[0] = 's';
        nw = 1;
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }

        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
            if (ans[3] == 'N') {
                ctx->error = 8;
                return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            if (ans[0] == 'N' && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7)
                    ctx->error = 8;
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    if (uid) {
        if (ctx->proto_mode) {
            memcpy(uids, ans + 3, sizeof(uids));
            nibble2dec(uid, uids);
        }
        else {
            ans[8] = 0;
            sscanf((char*) ans, "%x", uid);
        }
    }

    ctx->error = 0;
    return ACR120_SUCCESS;
}

/**
 * Key ff binary sequence: 02 01 04 6c 01 ff 0d 9a 03 
 * Key aa or bb binary sequence: 02 01 09 6c 01 aa a0 a1 a2 a3 a4 a5 ce 03
 **/
int acr120_login(acr120_ctx *ctx, unsigned char sector, 
                mifare_key type, unsigned char *key)
{
    int ret, i;
    unsigned char cmd[18], ans[6];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[3] = 'l';
        cmd[4] = sector;

        if (type == MIFARE_KEY_FF) {
            cmd[2] = 4;
            cmd[5] = 0xff;
            cmd[6] = 0xd;
            for (i = 1, cmd[7] = 0; i < 7; i++)
                cmd[7] ^= cmd[i];
            nw = 9;
        } else {
            cmd[2] = 9;
            cmd[5] = (type == MIFARE_KEY_AA) ? 0xaa : 0xbb;
            memcpy(cmd + 6, key, 6);
            for (i = 1, cmd[12] = 0; i < 12; i++)
                cmd[12] ^= cmd[i];
            nw = 14;
        }
        cmd[nw - 1] = ETX;
        nr = sizeof(ans);
    } else {
        if (type == MIFARE_KEY_FF)
            snprintf((char*) cmd, sizeof(cmd), "l%.2xffffffffffffff", sector);
        else
            snprintf((char*) cmd, sizeof(cmd), "l%.2x%s%.2x%.2x%.2x%.2x%.2x%.2x",
                     sector, (type == MIFARE_KEY_AA) ? "aa" : "bb",
                     key[0], key[1], key[2], key[3], key[4], key[5]);
        nw = sizeof(cmd) - 1;
        nr = 3;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (bytes > 3 && ans[2] == 1 && ctx->proto_mode) {
err:
            switch (ans[3]) {
                case 'L':
                    check_error(ctx, ans, nr);
                    ctx->error = 0;
                    return ACR120_SUCCESS;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'F':
                    ctx->error = 10;
                    return ACR120_ERROR;
                case 'E':
                    ctx->error = 11;
                    return ACR120_ERROR;
            }
        }

        /*
         * ASCII mode, there are only 3 bytes reply for success and error.
         */
        if (!ctx->proto_mode && bytes == 3)
            goto err;
    }

    ctx->error = 10;
    return ACR120_ERROR;
}

int acr120_write_block(acr120_ctx *ctx, unsigned char block, unsigned char *data)
{
    int ret, i;
    unsigned char cmd[37], ans[34];
    size_t bytes = 0, nr, nw;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 18;
        cmd[3] = 'w';
        cmd[4] = block;
        memcpy(cmd + 5, data, 16);
        cmd[22] = ETX;

        for (i = 1, cmd[21] = 0; i < 21; i++)
            cmd[21] ^= cmd[i];

        nw = 23;
        nr = 21;
    } else {
        snprintf((char*) cmd, sizeof(cmd), "w%.2x"
                 "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x"
                 "%.2x%.2x%.2x%.2x%.2x%.2x%.2x%.2x", 
                 block & 0xff, 
                 data[0], data[1], data[2], data[3], 
                 data[4], data[5], data[6], data[7], 
                 data[8], data[9], data[10], data[11],
                 data[12], data[13], data[14], data[15]);
        nw = 35;
        nr = sizeof(ans);
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    ctx->error = 13;
                    return ACR120_ERROR;
                case 'U':
                    ctx->error = 14;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'F':
                case 'I':
                    ctx->error = 15;
                    return ACR120_ERROR;
            }
        }

        /*
         * ASCII mode, so lets check for any operation error if we reached
         * at least 3 bytes (the minimal reply length in ASCII mode).
         * Lets read for more reply data, if we timeout, that is very likely 
         * data has been transmitted completely.
         */
        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'F' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;

                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_write_value(acr120_ctx *ctx, unsigned char block, unsigned int value)
{
    int ret, i;
    unsigned char cmd[12], data[4], ans[10];
    size_t bytes = 0, nr, nw;

    dec2nibble(value, data);

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x7;
        cmd[3] = 'w';
        cmd[4] = 'v';
        cmd[5] = block;
        cmd[6] = data[0];
        cmd[7] = data[1];
        cmd[8] = data[2];
        cmd[9] = data[3];
        cmd[11] = ETX;

        for (i = 1, cmd[10] = 0; i < 10; i++)
            cmd[10] ^= cmd[i];
        nw = sizeof(cmd);
        nr = 9;
    } else {
        sprintf((char*) cmd, "wv%.2x%.2x%.2x%.2x%.2x", block,
                 data[0], data[1], data[2], data[3]);
        nw = sizeof(cmd);
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        ret = acr120_timeout(ctx, ctx->io_timeo);
        if (ret == ACR120_ERROR)
            return ret;

rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                   ctx->error = 13;
                   return ACR120_ERROR;
                case 'U':
                    ctx->error = 14;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'F':
                case 'I':
                    ctx->error = 15;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'F' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);

                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_write_register(acr120_ctx *ctx, unsigned char reg, unsigned char value)
{
    unsigned char cmd[9], ans[6];
    size_t bytes = 0, nr, nw;
    int ret;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x4;
        cmd[3] = 'w';
        cmd[4] = 'e';
        cmd[5] = reg;
        cmd[6] = value;
        cmd[7] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5] ^ cmd[6];
        cmd[8] = ETX;
        nw = sizeof(cmd);
        nr = sizeof(ans);
    } else {
        snprintf((char*) cmd, 7, "we%.2x%.2x", reg, value);
        nw = 6;
        nr = 4;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }

        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    ctx->error = 13;
                    return ACR120_ERROR;
                case 'U':
                    ctx->error = 14;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                    ctx->error = 15;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout (ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_read_block(acr120_ctx *ctx, unsigned char block, unsigned char *data)
{
    int ret;
    unsigned char cmd[7], ans[34];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 2;
        cmd[3] = 'r';
        cmd[4] = block;
        cmd[5] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4];
        cmd[6] = ETX;
        nw = sizeof(cmd);
        nr = 21;
    } else {
        snprintf((char*) cmd, 4, "r%.2x", block);
        nw = 3;
        nr = sizeof(ans);
    }

    bytes = 0;
    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'F':
                    ctx->error = 12;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' || ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    if (data) {
        if (ctx->proto_mode)
            memcpy(data, ans + 3, 16);
        else {
            char hex[3];
            int i, j;
            for (i = 0, j = 0; i < 16; i++, j += 2) {
                snprintf(hex, 3, "%s", ans + j);
                data[i] = strtol(hex, NULL, 16);
            }
        }
    }
    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_read_value(acr120_ctx *ctx, unsigned char block, unsigned int *value)
{
    int ret;
    unsigned char cmd[8], ans[10], data[4];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x3;
        cmd[3] = 'r';
        cmd[4] = 'v';
        cmd[5] = block;
        cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
        cmd[7] = ETX;
        nw = sizeof(cmd);
        nr = 9;
    } else {
        snprintf((char*) cmd, 5, "rv%.2x", block);
        nw = 4;
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 0x1) {
err:
            switch (ans[3]) {
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                   ctx->error = 9;
                   return ACR120_ERROR;
                case 'F':
                   ctx->error = 12;
                   return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' || ans[0] == 'I' || ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    if (value) {
        if (ctx->proto_mode) {
            memcpy(data, ans + 3, sizeof(data));
            nibble2dec(value, data);
        } else {
            ans[sizeof(ans) - 2] = 0;
            sscanf((char*) ans, "%x", value);
        }
    }
    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_read_register(acr120_ctx *ctx, unsigned char reg, unsigned char *value)
{
    int ret;
    unsigned char cmd[8], ans[6];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x3;
        cmd[3] = 'r';
        cmd[4] = 'e';
        cmd[5] = reg;
        cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
        cmd[7] = ETX;
        nw = sizeof(cmd);
        nr = sizeof(ans);
    } else {
        snprintf((char *) cmd, 5, "re%02x", reg);
        nw = 4;
        nr = 4;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                    ctx->error = 9;
                    return ACR120_ERROR;
                case 'F':
                    ctx->error = 12;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' ||
                              ans[1] == 'I' ||
                              ans[2] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);
    if (ctx->proto_mode)
        *value = ans[3];
    else {
        ans[2] = 0;
        *value = strtol((char*) ans, 0, 16);
    }

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_copy_block(acr120_ctx *ctx, unsigned char source, unsigned char dest)
{
    int ret;
    unsigned char cmd[8], ans[10];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 0x3;
        cmd[3] = '=';
        cmd[4] = source;
        cmd[5] = dest;
        cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
        cmd[7] = ETX;
        nw = sizeof(cmd);
        nr = 9;
    } else {
        snprintf((char*) cmd, 6, "=%02x%02x", source, dest);
        nw = 5;
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    ctx->error = 21;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                    ctx->error = 9;
                    return ACR120_ERROR;
                case 'F':
                    ctx->error = 22;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);

                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                } else
                    return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_inc_value(acr120_ctx *ctx, unsigned char block, unsigned int inc)
{
    int ret, i;
    unsigned char cmd[12], ans[10], data[4];
    size_t bytes = 0, nr, nw;

    dec2nibble(inc, data);

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 6;
        cmd[3] = '+';
        cmd[4] = block;
        cmd[5] = data[0];
        cmd[6] = data[1];
        cmd[7] = data[2];
        cmd[8] = data[3];
        cmd[10] = ETX;

        for (i = 1, cmd[9] = 0; i < 9; i++)
            cmd[9] ^= cmd[i];

        nw = 11;
        nr = 9;
    } else {
        sprintf((char*) cmd, "+%.2i%.2i%.2i%.2i%.2i", block & 0xff,
                data[0], data[1], data[2], data[3]);
        nw = 11;
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < sizeof(ans)) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(ctx->fd, ans + bytes, sizeof(ans) - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    ctx->error = 16;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                    ctx->error = 9;
                    return ACR120_ERROR;
                case 'F':
                    ctx->error = 17;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_dec_value(acr120_ctx *ctx, unsigned char block, unsigned int dec)
{
    int ret, i;
    unsigned char cmd[12], ans[10], data[4];
    size_t bytes = 0, nr, nw;

    dec2nibble(dec, data);

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 6;
        cmd[3] = '-';
        cmd[4] = block;
        cmd[5] = data[0];
        cmd[6] = data[1];
        cmd[7] = data[2];
        cmd[8] = data[3];
        cmd[10] = ETX;

        for (i = 1, cmd[9] = 0; i < 9; i++)
            cmd[9] ^= cmd[i];
        nw = 11;
        nr = 9;
    } else {
        sprintf((char*) cmd, "-%.2i%.2i%.2i%.2i%.2i", block,
                data[0], data[1], data[2], data[3]);
        nw = 11;
        nr = 10;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (ctx->proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch(ans[3]) {
                case 'X':
                    ctx->error = 18;
                    return ACR120_ERROR;
                case 'N':
                    ctx->error = 8;
                    return ACR120_ERROR;
                case 'I':
                    ctx->error = 9;
                    return ACR120_ERROR;
                case 'F':
                case 'E':
                    ctx->error = 19;
                    return ACR120_ERROR;
            }
        }

        if (!ctx->proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F' ||
                              ans[0] == 'E';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(ctx, ctx->io_timeo);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && ctx->error == 7) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_power_on(acr120_ctx *ctx)
{
    int ret;
    unsigned char cmd[8], ans[6];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 3;
        cmd[3] = 'p';
        cmd[4] = 'o';
        cmd[5] = 'n';
        cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
        cmd[7] = ETX;

        nw = sizeof(ans);
        nr = sizeof(cmd);
    } else {
        cmd[0] = 'p';
        cmd[1] = 'o';
        cmd[2] = 'n';

        nw = 3;
        nr = 3;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ret;
        }
        bytes += ret;
    }

    /* 
     * Actually no error condition answer here, but the
     * reader will send 6 bytes of characters reply, so we 
     * only receive the buffer to make sure it is empty 
     */
    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

int acr120_power_off(acr120_ctx *ctx)
{
    int ret;
    unsigned char cmd[9], ans[6];
    size_t bytes = 0, nw, nr;

    if (ctx->proto_mode) {
        cmd[0] = STX;
        cmd[1] = ctx->station_id;
        cmd[2] = 4;
        cmd[3] = 'p';
        cmd[4] = 'o';
        cmd[5] = 'f';
        cmd[6] = 'f';
        cmd[7] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5] ^ cmd[6];
        cmd[8] = ETX;

        nw = sizeof(cmd);
        nr = sizeof(ans);
    } else {
        cmd[0] = 'p';
        cmd[1] = 'o';
        cmd[2] = 'f';
        cmd[3] = 'f';

        nw = 4;
        nr = 3;
    }

    while (bytes < nw) {
        ret = write(ctx->fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            ctx->error = 4;
            return ret;
        }
    }

    bytes = 0;
    while (bytes < nr) {
        if (ctx->io_timeo != 0) {
            ret = acr120_timeout(ctx, ctx->io_timeo);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(ctx->fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            ctx->error = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    check_error(ctx, ans, nr);

    ctx->error = 0;
    return ACR120_SUCCESS;
}

