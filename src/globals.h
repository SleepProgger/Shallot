#ifndef GLOBALS_H
#define GLOBALS_H

#include "config.h"

#include <regex.h>
#include <stdint.h>
#include <pthread.h>
#include "thread.h"


// global variables (saves us the trouble of passing pointers around)
// At least they are not clogging the namespace anymore.
// TODO: stop being lazy and pass this stuff where it's needed
struct globals_t{
  uint64_t elim, hits;
  uint8_t found, monitor, verbose;
  unsigned long int maxexectime;
  pthread_t lucky_thread;
  char *regex_str; // TODO: move to worker_param_t

  pthread_mutex_t print_mutex;

  struct worker_param_t *worker;
  int worker_n;
};
struct globals_t globals;

#endif
