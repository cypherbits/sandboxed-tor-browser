/**
 * tbb_stub.c: Sandboxed Tor Browser Firefox LD_PRELOAD stub.
 * Copyright (C) 2016  Yawning Angel.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This is a stub used to make Firefox work with sandboxed-tor-browser.
 * It is loaded at runtime via LD_PRELOAD, and is responsible for fixing
 * a number of issues that ordinarily would require patching the Firefox
 * source code.
 *
 * It is not intended to be used by anything except for sandboxed-tor-browser,
 * and anyone that attempts to do so will be laughed at.
 */

#define _GNU_SOURCE /* Fuck *BSD and Macintoys. */

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_socket)(int, int, int) = NULL;
static void *(*real_dlopen)(const char *, int) = NULL;
static int (*real_pthread_attr_getstack)(const pthread_attr_t *, void **, size_t *);
static struct sockaddr_un socks_addr;
static struct sockaddr_un control_addr;
static void *cached_environ;
extern char **environ;

#define SYSTEM_SOCKS_PORT 9050
#define SYSTEM_CONTROL_PORT 9051
#define TBB_SOCKS_PORT 9150
#define TBB_CONTROL_PORT 9151

int
connect(int fd, const struct sockaddr *address, socklen_t address_len)
{
  struct sockaddr *replaced_addr = NULL;
  struct sockaddr_in *in_addr = NULL;

  if (address == NULL || address_len < sizeof(struct sockaddr)) {
    errno = EINVAL;
    return -1;
  }

  /* Fast path for non-outgoing sockets. */
  if (address->sa_family == AF_LOCAL) {
    return real_connect(fd, address, address_len);
  }

  /* Unless something really goofy is going on, we should only ever have
   * AF_LOCAL or AF_INET sockets.  Enforce this.
   */
  if (address->sa_family != AF_INET || address_len < sizeof(struct sockaddr_in)) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  /* Demultiplex based on port.  In an ideal world, this should be
   * TOR_[SOCKS,CONTROL]_PORT based, but I'm lazy and they're both totally
   * arbitrary and only used to demux, so fuck it, whatever.
   */
  in_addr = (struct sockaddr_in*)address;

  switch (ntohs(in_addr->sin_port)) {
    case SYSTEM_SOCKS_PORT: /* FALLSTHROUGH */
    case TBB_SOCKS_PORT:
      replaced_addr = (struct sockaddr *)&socks_addr;
      break;
    case SYSTEM_CONTROL_PORT: /* FALLSTHROUGH */
    case TBB_CONTROL_PORT:
      replaced_addr = (struct sockaddr *)&control_addr;
      break;
    default:
      errno = EHOSTUNREACH;
      return -1;
  }

  return real_connect(fd, replaced_addr, sizeof(struct sockaddr_un));
}

int
socket(int domain, int type, int protocol)
{
  /* Replace AF_INET with AF_LOCAL. */
  if (domain == AF_INET)
    domain = AF_LOCAL;

  /* Only allow AF_LOCAL (aka AF_UNIX) sockets to be constructed. */
  if (domain != AF_LOCAL) {
    errno = EAFNOSUPPORT;
    return -1;
  }

  return real_socket(domain, type, protocol);
}

static int
has_prefix(const char *a, const char *b) {
  return strncmp(a, b, strlen(b)) == 0;
}

void *
dlopen(const char *filename, int flags)
{
  void *ret;

  if (filename != NULL) {
    if (has_prefix(filename, "libgnomeui"))
      return NULL;
    if (has_prefix(filename, "libgconf"))
      return NULL;
  }

  ret = real_dlopen(filename, flags);
#if 0
  /* This is useful for debugging the internal/dynlib package. */
  fprintf(stderr, "tbb_stub: dlopen('%s', %d) returned %p\n", filename, flags, ret);
#endif
  return ret;
}

/* There are rumors that PI futexes have scary race conditions, that enable
 * an exploit that is being sold by the forces of darkness.  On systems where
 * we can filter futex kernel args, we reject such calls.
 *
 * However this breaks certain versions of PulseAudio, because PI futex
 * usage is determined at compile time.  This fixes up the mutex creation
 * call to never request PI mutexes.
 *
 * The code in master may be better, since it looks like it shouldn't assert,
 * but god only knows what glibc does, when I ENOSYS their futex calls.
 *
 * Thanks to the unnamed reporter who filed the issues on the tails, bug
 * tracker and chatted with me on IRC about it.
 * See: https://labs.riseup.net/code/issues/11524
 */
typedef struct pa_mutex {
  pthread_mutex_t mutex;
} pm;

pm *
pa_mutex_new(bool recursive, bool inherit_priority) {
  int i;
  pthread_mutexattr_t attr;
  pm *m;
  (void) inherit_priority;

  if ((i = pthread_mutexattr_init(&attr)) != 0) {
    fprintf(stderr, "ERROR: pthread_mutexattr_init(): %d\n", i);
    abort();
  }
  if (recursive) {
    if ((i = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) != 0) {
      fprintf(stderr, "ERROR: pthread_mutexattr_settype(PTHREAD_MUTEX_RECURSIVE): %d\n", i);
      abort();
    }
  }

  m = malloc(sizeof(*m));
  if (m == NULL) {
    fprintf(stderr, "ERROR: Failed to allocate PulseAudio mutex\n");
    abort();
  }

  if ((i = pthread_mutex_init(&m->mutex, &attr)) != 0) {
    fprintf(stderr, "ERROR: pthread_mutex_init(): %d\n", i);
    abort();
  }

  return m;
}

/* This call appears to only be used as part of the `gconf` module to execute
 * a hardcoded `gconf-helper`, and isn't exposed to IPC.  So leaving it in
 * should be relatively harmless.  Might as well stub it out, though the
 * utility of doing so is questionable, since nothing should call it.
 *
 * See: https://labs.riseup.net/code/issues/12325
 */
int
pa_start_child_for_read(const char *name, const char *argv1, pid_t *pid)
{
#if 0
  fprintf(stderr, "tbb_stub: pa_start_child_for_read(%s, %p, %p)\n", name, argv1, pid);
#else
  (void) name;
  (void) argv1;
  (void) pid;
#endif
  return -1;
}

/* Firefox will crash if pthread_attr_getstack doesn't return a sensible stack
 * size, which will happen if /proc is missing, since glibc grovels through
 * /proc/self/maps to determine this information for the default thread.
 *
 * See: glibc/nptl/pthread_getattr_np.c
 */
int
pthread_attr_getstack(const pthread_attr_t *attr, void **stackaddr, size_t *stacksize)
{
  int ret;

  ret = real_pthread_attr_getstack(attr, stackaddr, stacksize);
  if (ret != 0) {
    fprintf(stderr, "WARN: pthread_attr_getstack(%p, %p, %p) = %d\n", attr, stackaddr, stacksize, ret);
    return ret;
  }

#if 0
  fprintf(stderr, "tbb_stub: pthread_attr_getstack(%p, %p, %p) = %d\n", attr, stackaddr, stacksize, ret);
  fprintf(stderr, "tbb_stub:  stackaddr: %p\n", *stackaddr);
  fprintf(stderr, "tbb_stub:  stacksize: %ld\n", *stacksize);
#endif

  /* If we got a sensible value for the stack size, then return. */
  if (*stacksize != 0) {
    return ret;
  } else {
    /* Otherwise, we should be the initial thread (pid == tid). */
    pid_t tid = syscall(__NR_gettid);
    pid_t pid = getpid();

    if (tid != pid) {
      fprintf(stderr, "ERROR: Got a 0 stack size when pid = %d != tid = %d\n", pid, tid);
      abort();
    }
  }

  /* First try pthread_attr_getstacksize(), which works on glibc 2.25. */
  ret = pthread_attr_getstacksize(attr, stacksize);
  if (ret != 0 || *stacksize == 0) {
    /* Fall back to getrlimit(). */
    struct rlimit rl;

    ret = getrlimit(RLIMIT_STACK, &rl);
    if (ret != 0) {
      fprintf(stderr, "ERROR: Failed to query rlimit: %d", ret);
      abort();
    }

    /* So, the main reason why glibc digs through proc is so that it can
     * return the current committed stack size, and not the upper bound on
     * the stack size.  But without /proc, there's no good way to get this
     * information.
     *
     * This is probably ok, pthread_attr_getstacksize() without proc mounted
     * appears to do the same thing.
     */
    *stacksize = rl.rlim_cur;
  }

  /* There is no easy way to derive this information, so do it the hard way. */
  if (*stackaddr == NULL) {
    /* WARNING: The arguments/env vars live on the stack, and are not
     * separate, so the result will be incorrect if more than a page
     * will be consumed, by up to 31 pages.
     */
    uintptr_t estimated_stackaddr = (uintptr_t)cached_environ;
    estimated_stackaddr &= ~(4096-1);
    estimated_stackaddr += 4096;
    estimated_stackaddr -= *stacksize;

    /* And check to see if the derived value appears to be sane. */
    uintptr_t p = (uintptr_t)&estimated_stackaddr;
    if (p > estimated_stackaddr && p < estimated_stackaddr+*stacksize) {
      *stackaddr = (void*)estimated_stackaddr;
    }
  }

#if 0
  fprintf(stderr, "tbb_stub: Fallback stackaddr: %p\n", *stackaddr);
  fprintf(stderr, "tbb_stub: Fallback stacksize: %ld\n", *stacksize);
#endif

  return ret;
}

/*  Initialize the stub. */
__attribute__((constructor)) static void
stub_init(void)
{
  char *socks_path = secure_getenv("TOR_STUB_SOCKS_SOCKET");
  char *control_path = secure_getenv("TOR_STUB_CONTROL_SOCKET");
  size_t dest_len = sizeof(socks_addr.sun_path);

  /* If `TOR_STUB_SOCKS_SOCKET` isn't set, bail. */
  if (socks_path == NULL) {
    fprintf(stderr, "ERROR: `TOR_STUB_SOCKS_SOCKET` enviornment variable not set.\n");
    goto out;
  }

  /* If `TOR_STUB_CONTROL_SOCKET` isn't set, bail. */
  if (control_path == NULL) {
    fprintf(stderr, "ERROR: `TOR_STUB_CONTROL_SOCKET` enviornment variable not set.\n");
    goto out;
  }

  /* Find the real symbols so we can call into libc after proccesing. */
  if ((real_connect = dlsym(RTLD_NEXT, "connect")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `connect()` symbol: %s\n", dlerror());
    goto out;
  }
  if ((real_socket = dlsym(RTLD_NEXT, "socket")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `socket()` symbol: %s\n", dlerror());
    goto out;
  }
  if ((real_pthread_attr_getstack = dlsym(RTLD_NEXT, "pthread_attr_getstack")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find `pthread_attr_getstack()` symbol: %s\n", dlerror());
    goto out;
  }

  /* Initialize the SOCKS target address. */
  socks_addr.sun_family = AF_LOCAL;
  strncpy(socks_addr.sun_path, socks_path, dest_len);
  socks_addr.sun_path[dest_len-1] = '\0';

  /* Initialize the Control target address. */
  control_addr.sun_family = AF_LOCAL;
  strncpy(control_addr.sun_path, control_path, dest_len);
  control_addr.sun_path[dest_len-1] = '\0';

  /* Tor Browser is built with GNOME integration, which is loaded dynamically
   * via dlopen().  This is fine and all, except that Firefox's idea of
   * handling "GMOME libraries present but the services are not running", is
   * to throw up a dialog box.
   *
   * There isn't a good way to fix this except via either rebuilding Firefox
   * or making the dlopen() call fail somehow.
   */
  if ((real_dlopen = dlsym(RTLD_NEXT, "dlopen")) == NULL) {
    fprintf(stderr, "ERROR: Failed to find 'dlopen()' symbol: %s\n", dlerror());
    goto out;
  }

  /* Save this since firefox at least will overwrite it. */
  cached_environ = environ;

  return;

out:
  abort();
}
