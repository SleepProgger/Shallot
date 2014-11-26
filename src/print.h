#ifndef PRINT_H
#define PRINT_H

#include <openssl/rsa.h>
#include <stdint.h>

void base32_enc (uint8_t *dst, uint8_t *src);
void base32_onion(char *dst, unsigned char *src);
void print_onion(char *onion);
void get_prkey(RSA *rsa, char *buffer);
void print_prkey(RSA *rsa);

#endif
