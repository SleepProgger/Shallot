#ifndef THREAD_H
#define THREAD_H

#include <stdint.h>
#include <regex.h>
#include "defines.h"

struct worker_param_t{
  uint64_t loops;
  uint8_t optimum;
  uint8_t keep_running;
  uint8_t recheck_hash;
  uint8_t (*check_method)(uint8_t*, char*, struct worker_param_t*);
  // Following variables are only set if the according check method is selected.
  regex_t *regex;
  char *word;
  int word_len;
};

struct monitor_param_t{
  uint8_t linebreak;
  uint8_t keep_running;
};

uint8_t find_regex(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data);
uint8_t find_cmp_s(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data);
uint8_t find_cmp_e(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data);

void *worker(void *params);
void *monitor_proc(void *unused);

#endif
