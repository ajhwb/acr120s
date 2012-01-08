/**
 *  ACS ACR-120S Smartcard Reader Library
 *  Copyright (C) 2009 - 2011, Ardhan Madras <ajhwb@knac.com>
 *
 *  Last modification: 04/02/2011
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
 *   ____________________________________________________________________
 *  |    STX    |    SID    | DATA LENGTH | CMD/DATA |   BCC   |   ETX   |
 *  |   1 byte  |   1 byte  |   1 byte    |  n bytes | 1 byte  |  1 byte |
 *  '-----------'-----------'-------------'----------'---------'---------'
 *
 **/

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


int acr120_errno;
static int acr120_proto_mode;
static struct termios old;

static void dec2nibble(unsigned int, unsigned char*);
static void nibble2dec(unsigned int*, unsigned char*);
static int check_bin_error(const unsigned char*, size_t);
static int check_ascii_error(const unsigned char*, size_t);
static int acr120_timeout(int, int);

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

#define check_error(ans, nr) \
do { \
if (acr120_proto_mode) { \
    if (check_bin_error(ans, (nr))) { \
        acr120_errno = 24; \
        return ACR120_ERROR; \
    } \
} else { \
    if (check_ascii_error(ans, (nr))) { \
        acr120_errno = 24; \
        return ACR120_ERROR; \
    } \
} \
} while (0);

static void dec2nibble(unsigned int value, unsigned char *nibble)
{
    nibble[3] = value & 0xff;
    nibble[2] = value >> 8 & 0xff;
    nibble[1] = value >> 16 & 0xff;
    nibble[0] = value >> 24 & 0xff;
}

static void nibble2dec(unsigned int *val, unsigned char *nibble)
{
    *val = nibble[3] | (nibble[2] << 8) | 
           (nibble[1] << 16) | (nibble[0] << 24);
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

const char* acr120_strerror(void)
{
    return acr120_error[acr120_errno - 1];
}

int acr120_change_speed(int fd, speed_t speed)
{
    int ret;
    struct termios opt;

    ret = tcgetattr(fd, &opt);
    if (ret == -1) {
        acr120_errno = 2;
        return ACR120_ERROR;
    }
    cfsetispeed(&opt, speed);
    cfsetospeed(&opt, speed);
    ret = tcsetattr(fd, TCSANOW, &opt);
    if (ret == -1) {
        acr120_errno = 4;
        return ACR120_ERROR;
    }
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_open(const char *dev, unsigned char sid, speed_t speed)
{
    int fd, ret;
    unsigned char cmd[8], ans[6], val;
    size_t bytes = 0;
    struct termios opt;

    fd = open(dev, O_RDWR | O_NOCTTY);
    if (fd == -1) {
        acr120_errno = 2;
        return ACR120_ERROR;
    }

    ret = tcgetattr(fd, &opt);
    if (ret == -1) {
        close(fd);
        acr120_errno = 4;
        return ACR120_ERROR;
    }

    /* 
     * Set to 8N1, save previous setting to restore on close.
     */
    memcpy(&old, &opt, sizeof(struct termios));

    cfsetispeed(&opt, speed);
    cfsetospeed(&opt, speed);

    opt.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    opt.c_iflag &= ~(INLCR | ICRNL | IXON | IXOFF);
    opt.c_oflag &= ~(ONLCR | OCRNL);
    opt.c_cflag &= ~(PARENB | CSTOPB | CSIZE);
    opt.c_cflag |= CS8;
    ret = tcsetattr(fd, TCSANOW, &opt);
    if (ret == -1) {
        close(fd);
        acr120_errno = 4;
        return ACR120_ERROR;
    }

    /*
     * Read protocol register to obtain protocol mode, let's try in 
     * ASCII mode first, if this fails goto BINARY mode.
     * Edane - Paraelit (Zep 170 Volts)
     */
    snprintf((char *) cmd, 5, "re%.2x", ACR120_REGISTER_PROTOCOL);
    while (bytes < 4) {
        ret = write(fd, cmd + bytes, 4 - bytes);
        if (ret <= 0) {
            acr120_errno = 5;
reset:
            tcsetattr(fd, TCSANOW, &old);
            close(fd);
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < 4) {
        ret = acr120_timeout(fd, -1);
        if (ret == ACR120_ERROR) {
            if (acr120_errno != 8)
                goto reset;
            goto bin;
        }

        ret = read(fd, ans + bytes, 4 - bytes);
        if (ret <= 0) {
            acr120_errno = 6;
            goto reset;
        }
        bytes += ret;
    }

    if (check_ascii_error(ans, 4)) {
        acr120_errno = 24;
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
    cmd[1] = sid;
    cmd[2] = 0x3;
    cmd[3] = 'r';
    cmd[4] = 'e';
    cmd[5] = ACR120_REGISTER_PROTOCOL;
    cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
    cmd[7] = ETX;

    bytes = 0;
    while (bytes < sizeof(cmd)) {
        ret = write(fd, cmd + bytes, sizeof(cmd) - bytes);
        if (ret <= 0) {
            acr120_errno = 5;
            goto reset;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < sizeof(ans)) {
        ret = acr120_timeout(fd, -1);
        if (ret == ACR120_ERROR)
            goto reset;
        ret = read(fd, ans + bytes, sizeof(ans) - bytes);
        if (ret <= 0) {
            acr120_errno = 6;
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
                    acr120_errno = 9;
                    goto reset;
                case 'I':
                    acr120_errno = 10;
                    goto reset;
                case 'F':
                    acr120_errno = 13;
                    goto reset;
            }
        }
    }

    if (check_bin_error(ans, sizeof(ans))) {
        acr120_errno = 24;
        goto reset;
    }
    val = ans[3];

done:
    /* Set protocol mode */
    acr120_proto_mode = val >> 1 & 0x1;
    acr120_errno = 1;
    return fd;
}

int acr120_close(int fd)
{
    int ret;

    /* Restore previous setting */
    ret = tcsetattr(fd, TCSANOW, &old);
    if (ret == -1) {
        acr120_errno = 4;
        return ACR120_ERROR;
    }
    ret = close(fd);
    if (ret == -1) {
        acr120_errno = 3;
        return ACR120_ERROR;
    }
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

#define REPLY_TIMEOUT   100000
#define USEC_PER_SEC    1000000

/*
 * Used for read operation timeout, REPLY_TIEMOUT time
 * (in miliseconds) should be a comfortable value.
 */
static int acr120_timeout(int fd, int timeout)
{
    int ret;
    fd_set rset;
    struct timeval val;

    FD_ZERO(&rset);
    FD_SET(fd, &rset);

    if (timeout < 0) val.tv_usec = REPLY_TIMEOUT;
    else if (timeout == 0) val.tv_usec = 0;
    else val.tv_usec = timeout * 1000;
    val.tv_sec = 0;

    while (val.tv_usec >= USEC_PER_SEC) {
        val.tv_sec++;
        val.tv_usec -= USEC_PER_SEC;
    }

    ret = select(fd + 1, &rset, NULL, NULL, &val);
    if (ret == 0) {
        acr120_errno = 8;
        return ACR120_ERROR;
    }
    if (ret == -1) {
        acr120_errno = 7;
        return ACR120_ERROR;
    }
    if (FD_ISSET(fd, &rset)) {
        acr120_errno = 1;
        return ACR120_SUCCESS;
    }
    /* Should be never here */
    acr120_errno = 7;
    return ACR120_ERROR;
}

int acr120_reset(int fd, unsigned char sid, int reply, int timeout)
{
    int ret;
    unsigned char cmd[6], ans[12];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
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
    while (reply && acr120_proto_mode && bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_get_id(int fd, unsigned char *id, int timeout)
{
    int ret;
    unsigned char cmd[6], ans[6];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    check_error(ans, nr);

    if (id)
        *id = acr120_proto_mode ? ans[3] : ans[0];

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_select(int fd, unsigned char sid, unsigned int *uid, int timeout)
{
    int ret;
    unsigned char cmd[6], ans[10], uids[4];
    size_t bytes = 0, nr, nw;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }

        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
            if (ans[3] == 'N') {
                acr120_errno = 9;
                return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            if (ans[0] == 'N' && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8)
                    acr120_errno = 9;
                return ret;
            }
        }
    }

    check_error(ans, nr);

    if (uid) {
        if (acr120_proto_mode) {
            memcpy(uids, ans + 3, sizeof(uids));
            nibble2dec(uid, uids);
        }
        else {
            ans[8] = 0;
            sscanf((char*) ans, "%x", uid);
        }
    }

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

/**
 * Key ff binary sequence: 02 01 04 6c 01 ff 0d 9a 03 
 * Key aa or bb binary sequence: 02 01 09 6c 01 aa a0 a1 a2 a3 a4 a5 ce 03
 **/
int acr120_login(int fd, unsigned char sid, unsigned char sector, 
                mifare_key type, unsigned char *key, int timeout)
{
    int ret, i;
    unsigned char cmd[18], ans[6];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (bytes > 3 && ans[2] == 1 && acr120_proto_mode) {
err:
            switch (ans[3]) {
                case 'L':
                    check_error(ans, nr);
                    acr120_errno = 1;
                    return ACR120_SUCCESS;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'F':
                    acr120_errno = 11;
                    return ACR120_ERROR;
                case 'E':
                    acr120_errno = 12;
                    return ACR120_ERROR;
            }
        }

        /*
         * ASCII mode, there are only 3 bytes reply for success and error.
         */
        if (!acr120_proto_mode && bytes == 3)
            goto err;
    }

    acr120_errno = 11;
    return ACR120_ERROR;
}

int acr120_write_block(int fd, unsigned char sid, unsigned char block, 
                unsigned char *data, int timeout)
{
    int ret, i;
    unsigned char cmd[37], ans[34];
    size_t bytes = 0, nr, nw;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    acr120_errno = 14;
                    return ACR120_ERROR;
                case 'U':
                    acr120_errno = 15;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'F':
                case 'I':
                    acr120_errno = 16;
                    return ACR120_ERROR;
            }
        }

        /*
         * ASCII mode, so lets check for any operation error if we reached
         * at least 3 bytes (the minimal reply length in ASCII mode).
         * Lets read for more reply data, if we timeout, that is very likely 
         * data has been transmitted completely.
         */
        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'F' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;

                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_write_value(int fd, unsigned char sid, unsigned char block, 
                unsigned int value, int timeout)
{
    int ret, i;
    unsigned char cmd[12], data[4], ans[10];
    size_t bytes = 0, nr, nw;

    dec2nibble(value, data);

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                   acr120_errno = 14;
                   return ACR120_ERROR;
                case 'U':
                    acr120_errno = 15;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'F':
                case 'I':
                    acr120_errno = 16;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'F' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout: -1);

                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_write_register(int fd, unsigned char sid, unsigned char reg,
                unsigned char value, int timeout)
{
    unsigned char cmd[9], ans[6];
    size_t bytes = 0, nr, nw;
    int ret;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }

        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    acr120_errno = 14;
                    return ACR120_ERROR;
                case 'U':
                    acr120_errno = 15;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                    acr120_errno = 16;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'U' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout (fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_read_block(int fd, unsigned char sid, unsigned char block, 
                unsigned char *data, int timeout)
{
    int ret;
    unsigned char cmd[7], ans[34];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'F':
                    acr120_errno = 13;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' || ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    if (data) {
        if (acr120_proto_mode)
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
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_read_value(int fd, unsigned char sid, unsigned char block,
                unsigned int *value, int timeout)
{
    int ret;
    unsigned char cmd[8], ans[10], data[4];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }

rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 0x1) {
err:
            switch (ans[3]) {
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                   acr120_errno = 10;
                   return ACR120_ERROR;
                case 'F':
                   acr120_errno = 13;
                   return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' || ans[0] == 'I' || ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    if (value) {
        if (acr120_proto_mode) {
            memcpy(data, ans + 3, sizeof(data));
            nibble2dec(value, data);
        } else {
            ans[sizeof(ans) - 2] = 0;
            sscanf((char*) ans, "%x", value);
        }
    }
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_read_register(int fd, unsigned char sid, unsigned char reg, 
                unsigned char *value, int timeout)
{
    int ret;
    unsigned char cmd[8], ans[6];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                    acr120_errno = 10;
                    return ACR120_ERROR;
                case 'F':
                    acr120_errno = 13;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'N' ||
                              ans[1] == 'I' ||
                              ans[2] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);
    if (acr120_proto_mode)
        *value = ans[3];
    else {
        ans[2] = 0;
        *value = strtol((char*) ans, 0, 16);
    }

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_copy_block(int fd, unsigned char sid, unsigned char source, 
                unsigned char dest, int timeout)
{
    int ret;
    unsigned char cmd[8], ans[10];
    size_t bytes = 0, nw, nr;

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    acr120_errno = 22;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                    acr120_errno = 10;
                    return ACR120_ERROR;
                case 'F':
                    acr120_errno = 23;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);

                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                } else
                    return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_inc_value(int fd, unsigned char sid, unsigned char block,
                unsigned int inc, int timeout)
{
    int ret, i;
    unsigned char cmd[12], ans[10], data[4];
    size_t bytes = 0, nr, nw;

    dec2nibble(inc, data);

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < sizeof(ans)) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(fd, ans + bytes, sizeof(ans) - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch (ans[3]) {
                case 'X':
                    acr120_errno = 17;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                    acr120_errno = 10;
                    return ACR120_ERROR;
                case 'F':
                    acr120_errno = 18;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_dec_value(int fd, unsigned char sid, unsigned char block,
                unsigned int dec, int timeout)
{
    int ret, i;
    unsigned char cmd[12], ans[10], data[4];
    size_t bytes = 0, nr, nw;

    dec2nibble(dec, data);

    if (acr120_proto_mode) {
        cmd[0] = STX;
        cmd[1] = sid;
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
        ret = write(fd, cmd + bytes, nw - bytes);
        if (ret == -1) {
            acr120_errno = 5;
            return ACR120_ERROR;
        }
        bytes += ret;
    }

    bytes = 0;
    while (bytes < nr) {
        if (timeout) {
            ret = acr120_timeout(fd, timeout);
            if (ret == ACR120_ERROR)
                return ret;
        }
rd:
        ret = read(fd, ans + bytes, nr - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;

        if (acr120_proto_mode && bytes > 3 && ans[2] == 1) {
err:
            switch(ans[3]) {
                case 'X':
                    acr120_errno = 19;
                    return ACR120_ERROR;
                case 'N':
                    acr120_errno = 9;
                    return ACR120_ERROR;
                case 'I':
                    acr120_errno = 10;
                    return ACR120_ERROR;
                case 'F':
                case 'E':
                    acr120_errno = 20;
                    return ACR120_ERROR;
            }
        }

        if (!acr120_proto_mode && bytes == 3) {
            int maybe_error = ans[0] == 'X' ||
                              ans[0] == 'N' ||
                              ans[0] == 'I' ||
                              ans[0] == 'F' ||
                              ans[0] == 'E';

            if (maybe_error && ans[1] == 0xd && ans[2] == 0xa) {
                ret = acr120_timeout(fd, timeout ? timeout : -1);
                if (ret == ACR120_SUCCESS)
                    goto rd;
                else if (ret == ACR120_ERROR && acr120_errno == 8) {
                    ans[3] = ans[0];
                    goto err;
                }
                return ret;
            }
        }
    }

    check_error(ans, nr);

    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_power_on(int fd, unsigned char sid, int timeout)
{
    int ret;
    unsigned char cmd[8], ans[6];
    size_t bytes = 0;

    cmd[0] = STX;
    cmd[1] = sid;
    cmd[2] = 3;
    cmd[3] = 'p';
    cmd[4] = 'o';
    cmd[5] = 'n';
    cmd[6] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5];
    cmd[7] = ETX;

    ret = write(fd, cmd, sizeof(cmd));
    if (ret == ACR120_ERROR) {
        acr120_errno = 5;
        return ret;
    }

    /* 
     * Actually no error condition answer here, but the
     * reader will send 6 bytes of characters reply, so we 
     * only receive the buffer to make sure it is empty 
     */
    while (bytes < sizeof(ans)) {
        if (timeout) {
            ret = acr120_timeout(fd, -1);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(fd, cmd + bytes, sizeof(cmd) - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;
    }
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

int acr120_power_off(int fd, unsigned char sid, int timeout)
{
    int ret;
    unsigned char cmd[9], ans[6];
    size_t bytes = 0;

    cmd[0] = STX;
    cmd[1] = sid;
    cmd[2] = 4;
    cmd[3] = 'p';
    cmd[4] = 'o';
    cmd[5] = 'f';
    cmd[6] = 'f';
    cmd[7] = cmd[1] ^ cmd[2] ^ cmd[3] ^ cmd[4] ^ cmd[5] ^ cmd[6];
    cmd[8] = ETX;

    ret = write(fd, cmd, sizeof(cmd));
    if (ret == ACR120_ERROR) {
        acr120_errno = 5;
        return ret;
    }
    while (bytes < sizeof(ans)) {
        if (timeout) {
            ret = acr120_timeout(fd, -1);
            if (ret == ACR120_ERROR)
                return ret;
        }
        ret = read(fd, cmd + bytes, sizeof(cmd) - bytes);
        if (ret == -1) {
            acr120_errno = 6;
            return ACR120_ERROR;
        }
        bytes += ret;
    }
    acr120_errno = 1;
    return ACR120_SUCCESS;
}

