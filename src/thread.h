#ifndef THREAD_H
#define THREAD_H

struct worker_param_t{
  uint8_t optimum;
  uint8_t keep_running;
};

void *worker(void *params);
void *monitor_proc(void *unused);

#endif
