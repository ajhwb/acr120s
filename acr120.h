/**
 *  ACS ACR-120S Smartcard Reader Library
 *  Copyright (C) 2009 - 2011, Ardhan Madras <ajhwb@knac.com>
 *
 *  Last modification: 03/29/2011
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
 */

#ifndef _ACR120_H
#define _ACR120_H

#include <termios.h>

#define ACR120_SUCCESS  0
#define ACR120_ERROR   -1

#define ACR120_REGISTER_STATIONID  0x4
#define ACR120_REGISTER_PROTOCOL   0x5
#define ACR120_REGISTER_BAUDRATE   0x6
#define ACR120_REGISTER_LED        0x7
#define ACR120_REGISTER_BUZZER     0x8


typedef enum {
    MIFARE_KEY_AA = 0,
    MIFARE_KEY_BB,
    MIFARE_KEY_FF
} mifare_key;

/*
 * Connection object representation for future versions :-)
 */
struct acr120_conn {
    struct termios opt;
    struct termios old;
    int fd;
    int error;
    unsigned char proto_mode;
};

extern int acr120_errno;

const char* acr120_strerror(void);

#ifdef __cplusplus
extern "C" {
#endif

int acr120_change_speed(int fd, speed_t speed);

int acr120_open(const char *dev, unsigned char sid, speed_t speed);

int acr120_close(int fd);

int acr120_reset(int fd, unsigned char sid, int reply, int timeout);

int acr120_get_id(int fd, unsigned char *id, int timeout);

int acr120_select(int fd, unsigned char sid, unsigned int *uid, int timeout);

int acr120_login(int fd, unsigned char sid, unsigned char sector, 
                mifare_key type, unsigned char *key, int timeout);
                
int acr120_write_block(int fd, unsigned char sid, unsigned char block, 
                unsigned char *data, int timeout);
                
int acr120_write_value(int fd, unsigned char sid, unsigned char block, 
                unsigned int value, int timeout);

int acr120_write_register(int fd, unsigned char sid, unsigned char reg,
                unsigned char value, int timeout);

int acr120_read_block(int fd, unsigned char sid, unsigned char block, 
                unsigned char *data, int timeout);
                
int acr120_read_value(int fd, unsigned char sid, unsigned char block,
                unsigned int *value, int timeout);

int acr120_read_register(int fd, unsigned char sid, unsigned char reg, 
                unsigned char *value, int timeout);

int acr120_copy_block(int fd, unsigned char sid, unsigned char source, 
                unsigned char dest, int timeout);
                
int acr120_inc_value(int fd, unsigned char sid, unsigned char block,
                unsigned int inc, int timeout);
                
int acr120_dec_value(int fd, unsigned char sid, unsigned char block,
                unsigned int dec, int timeout);
                
int acr120_power_on(int fd, unsigned char sid, int timeout);

int acr120_power_off(int fd, unsigned char sid, int timeout);

#ifdef __cplusplus
}
#endif

#endif

