/* program: shallot (based on the popular onionhash program by Bebop)
 * version: 0.0.2
 * purpose: brute-force customized SHA1-hashes of RSA keys for Tor's
 *          .onion namespace
 * license: OSI-approved MIT License
 * credits: Bebop, for onionhash, which credits the following:
 *          - Plasmoid         (The Hacker's Choice)
 *          - Roger Dingledine (Tor Project)
 *          - Nick Mathewson   (Tor Project)
 *          - Eric Young       (OpenSSL Project)
 *
 *          I would also like to thank the following testers/benchmarkers:
 *          - seeess         (Linux)
 *          - Cheeze-        (Linux, OS X)
 *          - Tas            (Linux, OS X, OpenBSD)
 *          - ^wAc^          (FreeBSD)
 *          - cybernetseraph (OpenBSD)
 *
 *          Special thanks to nickm for some debugging assistance!
 *          Extra-special thanks to Tas for his patience and assistance
 *            in getting shallot to build on OpenBSD, OS X, and Linux
 *
 * contact: mention bugs to <`Orum@OFTC or `Orum@ORC>
 */

/* TODO:
 * - finish all TODOs
 * - allow -m to be used with -f (use file for status output) [v0.0.3]
 * from ../TODO import * ;)
 */

#include "config.h"

#include "math.h"
#include "error.h"
#include "print.h"
#include "thread.h"
#include "defines.h"
#include "globals.h"

#ifdef LINUX_PORT
// Linux specific headers
#include "linux.h"
#include <fcntl.h>
#include <string.h> // included with something else on *BSD
#include <sys/uio.h>
#endif

#ifdef BSD
// BSD specific headers
#include <sys/param.h> // needed on OpenBSD
#include <sys/sysctl.h>
#endif

#ifdef WIN32
#include <windows.h>
#endif

#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ctype.h>

void terminate(int signum) { // Ctrl-C/kill handler
  error(X_SGNL_INT_TERM);
}


// TODO: move somewhere else (print ?)
// Validate part of an onion address.
// If valid and lowercase is set the str will be all lowercase after this function.
uint8_t valid_onion_part(char *str, int len, uint8_t lowercase){
  if(len > 16) return 0;
  int i;
  for (i = 0; i < len; ++i) {
    if(lowercase) str[i] = tolower(str[i]);
    if( !((str[i] >= 'a' && str[i] <= 'z') || (str[i] >= '2' && str[i] <= '7'))) return 0;
  }
  return 1;
}


int main(int argc, char *argv[]) { // onions are fun, here we go
  signal(SIGTERM, terminate); // always let people kill

  if(argc < 2) // not enough arguments
    usage();

  // set up our initial values
  uint8_t daemon = 0;
  uint32_t threads = 1, x = 1;
  char *file = 0;
  globals.elim = DEFAULT_E_LIMIT;
  globals.found = 0;
  globals.monitor = 0;
  globals.verbose = 0;
  globals.check_type = 'r';
  pthread_mutex_init(&globals.print_mutex, NULL );
  struct worker_param_t worker_param;
  worker_param.keep_running = 0;
  worker_param.optimum = 0;
  worker_param.loops = 0;
  worker_param.check_method = find_regex;
  worker_param.recheck_hash = 1;

  #ifdef BSD                                   // my
  int mib[2] = { CTL_HW, HW_NCPU };            // how
  size_t size = sizeof(threads);               // easy
  if(sysctl(mib, 2, &threads, &size, NULL, 0)) // BSD
    error(X_SYSCTL_FAILED);                    // is

  #elif defined(LINUX_PORT) // Oh no!  We're on Linux... :(
  // ...even *Windows 95* (gasp!) has a better way of doing this...
  // TODO: move this to linux.c
  char cpuinfo[CPUINFO_BUF_SIZE] = "";
  int fd = open(CPUINFO_PATH, O_RDONLY);

  if(fd < 0)
    error(X_BAD_FILE_DESC);

  threads--; // reset threads to 0
  size_t r = 0;
  ssize_t tmp = 1; // must not initially be 0!
  uint16_t used = 0;

  do {
    if(tmp)
      tmp = read(fd, &cpuinfo[r], CPUINFO_BUF_SIZE - r); // fill the buffer

    if(tmp < 0) // something went wrong
      error(X_ABNORMAL_READ);

    r += tmp; // add how much we read

    if(r < CPUINFO_BUF_SIZE)
      cpuinfo[r] = 0;

    threads += parse_cpuinfo(&cpuinfo[0], (uint16_t)r, &used);
    r -= used; // subtract what we parsed

    memmove(&cpuinfo[0], &cpuinfo[used], r);
  } while(used > 0);

  close(fd); // TODO: add error handling! (is there any point?)

  if(!threads) { // This is needed for Linux/ARM (do not remove!)
    printf("WARNING: No CPUs detected.  Defaulting to 1 thread... "
           "(or manually specify thread count with -t)\n");
    threads++;
  }

  #elif defined(GENERIC)
  printf("WARNING: Threads will default to 1 unless specified with -t\n");
  #endif

  // pattern help
  if( argc >= x)
  {
    if( strcmp(argv[x], "-p") == 0)
    {
      pattern();
    }
  }


  for(; x < argc - 1; x++) { // options parsing
    if(argv[x][0] != '-') {
      fprintf(stderr, "Error: Options must start with '-'\n");
      usage();
    }
    uint32_t y = 1;
    for(; argv[x][y] != '\0'; y++) {
      uint8_t dbreak = 0;
      switch(argv[x][y]) {
        case 'v': { // verbose
          if(globals.verbose < 255) globals.verbose++;
          break;
        }
        case 'r': { // recheck
          worker_param.recheck_hash = 0;
          break;
        }
        case 'h': { // verbose
          usage();
          break;
        }
        case 'd': { // daemonize
          daemon = 1;
          break;
        }
        case 'm': { // monitor
          globals.monitor = 1;
          break;
        }
        case 'o': { // prime optimization
          worker_param.optimum = 1;
          break;
        }
        case 'k': {
          worker_param.keep_running = 1;
          break;
        }
        case 'f': { // file <file>
          if((argv[x][y + 1] != '\0') || (x + 1 >= argc)) {
            fprintf(stderr, "Error: -f format is '-f <file>'\n");
            usage();
          }
          file = argv[x + 1];
          dbreak = 1;
          break;
        }
        case 't': { // threads
          if((argv[x][y + 1] != '\0') || (x + 1 >= argc)) {
            fprintf(stderr, "Error: -t format is '-t threads'\n");
            fflush(stderr);
            usage();
          }
          threads = strtoul(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }
        case 'x': { // maximum execution time
          if((argv[x][y + 1] != '\0') || (x + 1 >= argc)) {
            fprintf(stderr, "Error: -x format is '-x <max exec time in seconds>'\n");
            usage();
          }
          globals.maxexectime = strtoul(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }

        case 'e': { // e limit
          if((argv[x][y + 1] != '\0') || (x + 1 >= argc)) {
            fprintf(stderr, "Error: -e format is '-e limit'\n");
            usage();
          }
          globals.elim = strtoull(argv[x + 1], NULL, 0);
          dbreak = 1;
          break;
        }

        case 'c': { // check method
          if((argv[x][y + 1] != '\0') || (x + 1 >= argc) || !(argv[x+1][0] == 'r' || argv[x+1][0] == 's' || argv[x+1][0] == 'e' )) {
            fprintf(stderr, "Error: -c format is '-c <r,s,e>'\n");
            usage();
          }
          if(argv[x+1][0] == 'r') worker_param.check_method = find_regex;
          else if(argv[x+1][0] == 's') worker_param.check_method = find_cmp_s;
          else if(argv[x+1][0] == 'e') worker_param.check_method = find_cmp_e;
          globals.check_type = argv[x+1][0];
          dbreak = 1;
          break;
        }

        default: { // unrecognized
          fprintf(stderr, "Error: Unrecognized option - '%c'\n", argv[x][y]);
          usage();
          break; // redundant... but safe :)
        }
      }
      if(dbreak) {
        x++; // skip the next param
        break;
      }
    }
  }

  // now for our sanity checks
  if(threads < 1)
    error(X_INVALID_THRDS);

  if(globals.monitor && file)
    error(X_EXCLUSIVE_OPT);

  if(!(globals.elim & 1) || (globals.elim < RSA_PK_EXPONENT) || (globals.elim > MAXIMUM_E_LIMIT))
    error(X_INVALID_E_LIM);

  if(daemon && !file)
    error(X_NEED_FILE_OUT);


  char *pattern = argv[argc - 1];
  int pat_len = strlen(pattern);
  if (globals.check_type == 'r'){
    // compile regular expression from argument
    if(*pattern == '-')
      error(X_REGEX_INVALID);
    regex_t *regex = malloc(REGEX_COMP_LMAX); // we already check it here and again in the threads atm...
    // TODO: drop the check in threads ?
    if(regcomp(regex, pattern, REG_EXTENDED | REG_NOSUB))
      error(X_REGEX_COMPILE);
    globals.regex_str = pattern; // TODO: move to worker_param ?
    regfree(regex);
  }else{
    if(!valid_onion_part(pattern, pat_len, 1)) error(X_INVALID_PATTERN);
    worker_param.word_len = pat_len;
    worker_param.word = pattern;
  }

  if(file) {
    umask(077); // remove permissions to be safe

    // redirect output
    if (
			(freopen(file, "w", stdout) == NULL) ||
			(freopen(file, "w", stderr) == NULL)
		) error(X_FILE_OPEN_ERR);
  }
#ifndef WIN32 // no -d flag for win for now
  if(daemon && (getppid() != 1)) { // daemonize if we should
    pid_t pid = fork();

    if(pid < 0) // fork failed
      error(X_DAEMON_FAILED);

    if(pid) // exit on the parent process
      exit(0);

    if(setsid() < 0) // get a new SID
      error(X_DAEMON_FAILED);

    if(chdir("/") < 0) // cd to root
      error(X_DAEMON_FAILED);

		// block input
    if (freopen("/dev/null", "r", stdin) == NULL)
			error(X_FILE_OPEN_ERR);

    // ignore certain signals
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGHUP,  SIG_IGN);
  } else signal(SIGINT, terminate); // die on CTRL-C
#else
signal(SIGINT, terminate); // die on CTRL-C
#endif


  if(globals.verbose > 1) fprintf(stderr, "Starting with: type: %c, threads: %i, optimum: %s, verbose: %i, keep-running: %s  \n",
      globals.check_type, threads, worker_param.optimum?"true":"false", globals.verbose, worker_param.keep_running?"true":"false");

  globals.worker_n = threads;
  globals.worker = (struct worker_param_t*) malloc(sizeof(struct worker_param_t)*threads);
  pthread_t thrd;
  // create our threads for 2+ cores
  for(x = 1; x < threads; x++) {
    memcpy(globals.worker+x, &worker_param, sizeof(struct worker_param_t));
    if(pthread_create(&thrd, NULL, worker, globals.worker+x))
      error(X_THREAD_CREATE);
  }
  memcpy(globals.worker, &worker_param, sizeof(struct worker_param_t));

  if(globals.monitor) {
    // TODO: when support is added for -mv, put a message here
    // TODO: use own param for monitor thread
    if(pthread_create(&thrd, NULL, monitor_proc, &worker_param))
      error(X_THREAD_CREATE);
  }

  worker(globals.worker); // use main thread for brute-forcing too


  // mingw uses a struct containing the pointer and additional data as pthread_t instead of a long.
  // This way we should be on the safe side ?.
  pthread_t tmp_ = pthread_self();
  if(memcmp(&tmp_, &globals.lucky_thread, sizeof(pthread_t)) == 0){
	  pthread_join(globals.lucky_thread, NULL); // wait for the lucky thread to exit
  }
  return 0;
}
