/**
 *  ACS ACR-120S Smartcard Reader Library
 *  Copyright (C) 2009 - 2013, Ardhan Madras <ajhwb@knac.com>
 *
 *  Last modification: 06/13/2013
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

enum {
    ACR120_BAUDRATE_9600 = 0,
    ACR120_BAUDRATE_19200,
    ACR120_BAUDRATE_38400,
    ACR120_BAUDRATE_57600,
    ACR120_BAUDRATE_115200
};

struct _acr120_ctx;

typedef struct _acr120_ctx acr120_ctx;

#ifdef __cplusplus
extern "C" {
#endif

int acr120_errno(acr120_ctx *ctx);

const char* acr120_strerror(acr120_ctx *ctx);

int acr120_change_baudrate(acr120_ctx *ctx, int baudrate);

acr120_ctx *acr120_init(const char *dev, int station_id, int baudrate, int timeout);

void acr120_free(acr120_ctx *ctx);

int acr120_reset(acr120_ctx *ctx, int need_reply);

int acr120_get_id(acr120_ctx*, unsigned char *id);

int acr120_select(acr120_ctx *ctx, unsigned int *uid);

int acr120_login(acr120_ctx *ctx, unsigned char sector, 
                mifare_key type, unsigned char *key);
                
int acr120_write_block(acr120_ctx *ctx, unsigned char block, const unsigned char *data);

int acr120_write_value(acr120_ctx *ctx, unsigned char block, unsigned int value);

int acr120_write_register(acr120_ctx *ctx, unsigned char reg, unsigned char value);

int acr120_read_block(acr120_ctx *ctx, unsigned char block, unsigned char *data);

int acr120_read_value(acr120_ctx *ctx, unsigned char block, unsigned int *value);

int acr120_read_register(acr120_ctx *ctx, unsigned char reg, unsigned char *value);

int acr120_copy_block(acr120_ctx *ctx, unsigned char source, unsigned char dest);

int acr120_inc_value(acr120_ctx *ctx, unsigned char block, unsigned int inc);

int acr120_dec_value(acr120_ctx *ctx, unsigned char block, unsigned int dec);

int acr120_power_on(acr120_ctx *ctx);

int acr120_power_off(acr120_ctx *ctx);

#ifdef __cplusplus
}
#endif

#endif /* _ACR120_H */

