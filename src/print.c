// printing functions for shallot

#include "config.h"

#include "print.h"
#include "defines.h"
#include "globals.h"
#include "error.h"

#include <stdio.h>
#include <string.h>
#include <openssl/pem.h>

// endian crap for htobe16() [only needed
// for base32_onion which should be moved] {
#include <stdint.h> // OpenBSD needs this included before sys/endian.h

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)
  #include "linux.h"
#else
  #include <sys/param.h> // OpenBSD needs this early on too
  #include <sys/endian.h>
#endif
//}

/* From Eschalot src- Only remaining src i found is: https://bitcointalk.org/index.php?topic=639410.0
 * Base32 encode 10 byte long 'src' into 16 character long 'dst' */
/* Experimental, unroll everything. So far, it seems to be the fastest of the
 * algorithms that I've tried. TODO: review and decide if it's final.*/
void base32_enc (uint8_t *dst, uint8_t *src)
{
  dst[ 0] = BASE32_ALPHABET[ (src[0] >> 3)          ];
  dst[ 1] = BASE32_ALPHABET[((src[0] << 2) | (src[1] >> 6)) & 31];
  dst[ 2] = BASE32_ALPHABET[ (src[1] >> 1)      & 31];
  dst[ 3] = BASE32_ALPHABET[((src[1] << 4) | (src[2] >> 4)) & 31];
  dst[ 4] = BASE32_ALPHABET[((src[2] << 1) | (src[3] >> 7)) & 31];
  dst[ 5] = BASE32_ALPHABET[ (src[3] >> 2)      & 31];
  dst[ 6] = BASE32_ALPHABET[((src[3] << 3) | (src[4] >> 5)) & 31];
  dst[ 7] = BASE32_ALPHABET[  src[4]        & 31];

  dst[ 8] = BASE32_ALPHABET[ (src[5] >> 3)          ];
  dst[ 9] = BASE32_ALPHABET[((src[5] << 2) | (src[6] >> 6)) & 31];
  dst[10] = BASE32_ALPHABET[ (src[6] >> 1)      & 31];
  dst[11] = BASE32_ALPHABET[((src[6] << 4) | (src[7] >> 4)) & 31];
  dst[12] = BASE32_ALPHABET[((src[7] << 1) | (src[8] >> 7)) & 31];
  dst[13] = BASE32_ALPHABET[ (src[8] >> 2)      & 31];
  dst[14] = BASE32_ALPHABET[((src[8] << 3) | (src[9] >> 5)) & 31];
  dst[15] = BASE32_ALPHABET[  src[9]        & 31];

  dst[16] = '\0';
}

/* From Eschalot src- Only remaining src i found is: https://bitcointalk.org/index.php?topic=639410.0
 * Decode base32 16 character long 'src' into 10 byte long 'dst'. */
/* TODO: Revisit and review, would like to shrink it down a bit.
 * However, it has to stay endian-safe and be fast. */
void base32_dec (uint8_t *dst, uint8_t *src)
{
  uint8_t   tmp[BASE32_ONIONLEN];
  unsigned int  i;

  for (i = 0; i < 16; i++) {
    if (src[i] >= 'a' && src[i] <= 'z') {
      tmp[i] = src[i] - 'a';
    } else {
      if (src[i] >= '2' && src[i] <= '7')
        tmp[i] = src[i] - '1' + ('z' - 'a');
      else {
        /* Bad character detected.
         * This should not happen, but just in case
         * we will replace it with 'z' character. */
        tmp[i] = 26;
      }
    }
  }
  dst[0] = (tmp[ 0] << 3) | (tmp[1] >> 2);
  dst[1] = (tmp[ 1] << 6) | (tmp[2] << 1) | (tmp[3] >> 4);
  dst[2] = (tmp[ 3] << 4) | (tmp[4] >> 1);
  dst[3] = (tmp[ 4] << 7) | (tmp[5] << 2) | (tmp[6] >> 3);
  dst[4] = (tmp[ 6] << 5) |  tmp[7];
  dst[5] = (tmp[ 8] << 3) | (tmp[9] >> 2);
  dst[6] = (tmp[ 9] << 6) | (tmp[10] << 1) | (tmp[11] >> 4);
  dst[7] = (tmp[11] << 4) | (tmp[12] >> 1);
  dst[8] = (tmp[12] << 7) | (tmp[13] << 2) | (tmp[14] >> 3);
  dst[9] = (tmp[14] << 5) |  tmp[15];
}

// TODO: Move to math.c?
void base32_onion(char *dst, unsigned char *src) { // base32-encode hash
  uint8_t byte = 0,   // dst location
          offset = 0; // bit offset
  for(; byte < BASE32_ONIONLEN; offset += 5) {
    if(offset > 7) {
      offset -= 8;
      src++;
    }
    dst[byte++] = BASE32_ALPHABET[(htobe16(*(uint16_t*)src) >> (11-offset))
                                  & (uint16_t)0x001F];
  }
  dst[byte] = '\0';
}

void print_onion(char *onion) { // pretty-print hash
  uint8_t i;
  char *s;
  int j = 0;
  uint64_t loops = 0;
  for (j = 0; j < globals.worker_n; loops+=globals.worker[j].loops, ++j);
  #ifdef GENERIC
  s = malloc(PRINT_ONION_MAX);
  snprintf(s, PRINT_ONION_MAX, PRINT_ONION_STR, loops, onion);
  #else
  if (asprintf(&s, PRINT_ONION_STR, loops, onion) == -1)
		error(X_OUT_OF_MEMORY);
  #endif
  for(i=0; i<strlen(s); i++)
    printf("-"); // TODO: use fputc()?
  printf("\n%s\n", s);
  for(i=0; i<strlen(s); i++)
    printf("-"); // TODO: use fputc()?
  printf("\n");
  free(s);
}

void get_prkey(RSA *rsa, char *buffer) { // print PEM formatted RSA key
  BUF_MEM *buf;
  BIO *b = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(b, rsa, NULL, NULL, 0, NULL, NULL);
  BIO_get_mem_ptr(b, &buf);
  (void)BIO_set_close(b, BIO_NOCLOSE);
  BIO_free(b);
  //char *dst = malloc(buf->length+1); // why don't we just write buf->data to stdout  here ?
  strncpy(buffer, buf->data, buf->length); // we trust the buffer is large enough here. TODO: test it ?
  buffer[buf->length] = '\0';
  BUF_MEM_free(buf);
}

void print_prkey(RSA *rsa) { // print PEM formatted RSA key
  BUF_MEM *buf;
  BIO *b = BIO_new(BIO_s_mem());
  PEM_write_bio_RSAPrivateKey(b, rsa, NULL, NULL, 0, NULL, NULL);
  BIO_get_mem_ptr(b, &buf);
  (void)BIO_set_close(b, BIO_NOCLOSE);
  BIO_free(b);
  char *dst = malloc(buf->length+1); // why don't we just write buf->data to stdout  here ?
  strncpy(dst, buf->data, buf->length);
  dst[buf->length] = '\0';
  printf("%s", dst);
  free(dst);
  BUF_MEM_free(buf);
}

