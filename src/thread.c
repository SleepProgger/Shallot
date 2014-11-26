// thread procs for shallot

#include "config.h"

#include <stdint.h> // OpenBSD needs this included before sys/endian.h

#if defined(LINUX_PORT) || defined(OSX) || defined(GENERIC)
  #include "linux.h"
#else
  #include <sys/param.h> // OpenBSD needs this early on too
  #include <sys/endian.h>
#endif

#include "math.h"
#include "print.h"
#include "error.h"
#include "thread.h"
#include "defines.h"
#include "globals.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

uint8_t find_regex(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data){
  base32_enc((uint8_t*)onion_buf, hash);
  return regexec(worker_data->regex, onion_buf, 0, 0, 0) == 0;
}
uint8_t find_cmp_s(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data){
  base32_enc((uint8_t*)onion_buf, hash);
  return memcmp(worker_data->word , onion_buf, worker_data->word_len) == 0;
}
uint8_t find_cmp_e(uint8_t *hash, char *onion_buf, struct worker_param_t *worker_data){
  base32_enc((uint8_t*)onion_buf, hash);
  return memcmp(worker_data->word, onion_buf + 16 - worker_data->word_len, worker_data->word_len) == 0;
}

void *worker(void *params_p) { // life cycle of a cracking pthread
  struct worker_param_t *params = params_p;
  uint64_t e_be; // storage for our "big-endian" version of e
  uint8_t buf[SHA1_DIGEST_LEN],
          der[RSA_EXP_DER_LEN + 1]; // TODO: is the size of this right?
  char onion[BASE32_ONIONLEN + 1];
  SHA_CTX hash, copy;
  RSA *rsa;
  char key_buf[2048]; // just to be sure
  memset(key_buf, 0, 2048);
  // use to check the own results as there as a bug leading to real onion addr != calculated one
  uint8_t buf_c[SHA1_DIGEST_LEN], der_c[RSA_EXP_DER_LEN + 1];
  uint8_t *ptr = der_c;
  size_t der_len;
  if(globals.check_type == 'r'){
    params->regex = malloc(REGEX_COMP_LMAX);
    printf("compile regex with start worker with word %s\n", params->word);
    if(regcomp(params->regex, globals.regex_str, REG_EXTENDED | REG_NOSUB)) // yes, this is redundant, but meh
      error(X_REGEX_COMPILE);
  }


  while(!globals.found) {
    // keys are only generated every so often
    // every 549,755,781,120 tries by default

    if(params->optimum)
      rsa = easygen(RSA_OPTM_BITLEN - RSA_PK_E_LENGTH * 8, RSA_PK_E_LENGTH,
                    der, RSA_OPT_DER_LEN, &hash);
    else
      rsa = easygen(RSA_KEYS_BITLEN, RSA_PK_E_LENGTH, der, RSA_EXP_DER_LEN,
                    &hash);

    if(!rsa) // if key generation fails (no [P]RNG seed?)
      error(X_KEY_GEN_FAILS);

    uint8_t e_bytes = RSA_PK_E_LENGTH; // number of bytes e occupies
    uint64_t e = RSA_PK_EXPONENT;      // public exponent
    uint64_t e_byte_thresh = 1;

    e_byte_thresh <<= e_bytes * 8;
    e_byte_thresh++;

    uint8_t *e_ptr = ((uint8_t*)&e_be) + 8 - e_bytes;

    while((e <= globals.elim) && !globals.found) { // main loop
      // copy the relevant parts of our already set up context
      memcpy(&copy, &hash, SHA_REL_CTX_LEN); // 40 bytes here...
      copy.num = hash.num;                   // and don't forget the num (9)

      // convert e to big-endian format
      e_be = htobe64(e);

      // compute SHA1 digest (majority of loop time spent here!)
      SHA1_Update(&copy, e_ptr, e_bytes);
      SHA1_Final(buf, &copy);

      params->loops++;
      if(params->check_method(buf, onion, params)) { // check for a match

        if(globals.monitor)
          printf("\n"); // keep our printing pretty!

        //BIGNUM *oldE = BN_dup(rsa->e);
        if(!BN_bin2bn(e_ptr, e_bytes, rsa->e)) // store our e in the actual key
          error(X_BIGNUM_FAILED);              // and make sure it got there

        if(!sane_key(rsa)){        // check our key
          if(globals.verbose > 0) fprintf(stderr, "\nERROR: You happened to find a bad key - congrats.\n");;
          break;
          //error(X_YOURE_UNLUCKY); // bad key :(
        }

        if(params->recheck_hash){
          // Create the (unencoded) onion address from a fresh exported public key,
          // and test it against out calculated one. Otherwise this tool produce wrong keys (rare).
          // (Try ^code or ^caaa as test search pattern. (Don't forget -v[v] when testing.)
          // TODO: comparing der should be enough (skip sha1 generation)
          ptr = der_c;
          der_len = i2d_RSAPublicKey(rsa, &ptr);
          SHA1_Init(&copy);
          SHA1_Update(&copy, der_c, der_len);
          SHA1_Final(buf_c, &copy);
          if (memcmp(buf, buf_c, 10) != 0) {
            //RSA_free(rsa); // free up what's left (wtf ? why does this crash ? it should be freed ?!)
            if(globals.verbose > 0) fprintf(stderr, "\nInvalid key found for %s. Skip this key.\n", onion);
            if(globals.verbose > 1){
              base32_onion(onion, buf_c);
              fprintf(stderr, "Real onion is %s.onion\n", onion);
              get_prkey(rsa, key_buf);
              fprintf(stderr, "%s\n", key_buf);
            }
            break;
          }
        }

        get_prkey(rsa, key_buf);
        pthread_mutex_lock(&globals.print_mutex);
        print_onion(onion); // print our domain
        fprintf(stdout, "%s\n", key_buf);   // and more importantly the key
        pthread_mutex_unlock(&globals.print_mutex);

        if(!params->keep_running){
          // let our main thread know on which thread to wait
          globals.lucky_thread = pthread_self();
          globals.found = 1; // kill off our other threads, asynchronously
          RSA_free(rsa); // free up what's left
          return 0;
        }
        //BN_copy(oldE, rsa->e);
        // We should be able to continue, but some call seem to change the der/rsa or e data.
        // Copying back the old rsa->e didn'T help. TODO: <-
        // So for now we just create a new rsa key and start fresh.
        globals.hits++;
        break;
      }

      e += 2; // do *** NOT *** forget this!

      if(e == e_byte_thresh) { // ASN.1 stuff (hey, it could be worse!)
        // calculate our new threshold
        e_byte_thresh <<= ++e_bytes * 8;
        e_byte_thresh++;

        if(params->optimum) {
          RSA_free(rsa);
          easygen(RSA_OPTM_BITLEN - e_bytes * 8, e_bytes, der, RSA_OPT_DER_LEN,
                  &hash);

          if(!rsa)
            error(X_KEY_GEN_FAILS);
        } else {
          // play with our key structure (do not try this at home!)
          der[RSA_ADD_DER_OFF]++;
          der[RSA_EXP_DER_LEN - RSA_PK_E_LENGTH - 1]++;

          // and our prebuilt hash
          SHA1_Init(&hash); // TODO: move to a function
          SHA1_Update(&hash, der, RSA_EXP_DER_LEN - RSA_PK_E_LENGTH);
        }

        e_ptr--; // and move the pointer back
      }
    }
    RSA_free(rsa);
  }
  if(globals.check_type == 'r') regfree(params->regex);
  return 0;
}

void *monitor_proc(void *params_p) {
  struct worker_param_t *params = params_p;
  fprintf(stderr,"\033[sPlease wait a moment for statistics...");
  time_t start, current, elapsed;
  uint64_t lloop = 0;
  start = time(NULL);
  int i;

  for(;;) {
    fflush(stderr); // make sure it gets printed
    //this next little section sleeps 20 seconds before continuing
    //and checks every second whether the maximum execution time (-x) has
    //been reached.
    for(i=0;i<20;i++){
      sleep(1);
      current = time(NULL);
      elapsed = current - start;
      if(elapsed>globals.maxexectime || elapsed==globals.maxexectime){
        if(globals.maxexectime > 0){
          error(X_MAXTIME_REACH);
        }
      }
    }


    if(globals.found)
      return 0;

    // This is not 100% accurate, but good enough imho
    current = time(NULL);
    elapsed = current - start;
    if(!elapsed)
      continue; // be paranoid and avoid divide-by-zero exceptions
    lloop = 0;
    for (i = 0; i < globals.worker_n; ++i) {
      lloop += globals.worker[i].loops;
    }
    fprintf(stderr,"\033[u\033[KHashes: %-20"PRIu64"  Time: %-10d  Speed: %-"PRIu64"",
        lloop, (int)elapsed, lloop / elapsed);
    if(params->keep_running) fprintf(stderr, "  Hits: %-5"PRIu64"", globals.hits);

  }

  return 0; // unreachable code, but prevents warnings (!?)
}
