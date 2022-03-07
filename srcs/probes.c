// Copyright (C) 2022 ESET spol. s r.o.
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

// SPDX-License-Identifier: GPL-2.0

#define BPF_LICENSE GPL
#include <linux/fs.h>
#include <linux/sched.h>
#include <net/sock.h>
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

struct paths {
  const char *source;
  const char *target;
};

struct accept_data {
  void *sockaddr;
  int *len;
  int fd;
};

// bpf entry probes have issues with reading memory of a fresh process
BPF_HASH(path_cache, u64, struct paths);

BPF_HASH(accept_cache, u64, struct accept_data);
BPF_HASH(connect_cache, u64, struct tcp_event);

static void save_paths(const char *source, const char *target) {
  u64 key = bpf_get_current_pid_tgid();
  struct paths value = {.source = source, .target = target};
  path_cache.update(&key, &value);
}

static void save_path(const char *source) { save_paths(source, NULL); }

static int getuid() { return bpf_get_current_uid_gid() & 0xffffffff; }
static int getgid() { return bpf_get_current_uid_gid() >> 32; }
static int gettgid() { return bpf_get_current_pid_tgid() >> 32; }
static int getkpid() { return bpf_get_current_pid_tgid() & 0xffffffff; }

static void init_header(void *_header, event_type_t event_type) {
  struct event_header *header = (struct event_header *)_header;
  header->event_type = event_type;
  header->timestamp = bpf_ktime_get_ns();
  header->pid_tgid = bpf_get_current_pid_tgid();
  header->uid = getuid();
  header->gid = getgid();
}

static void init_path_event(struct path_event *event, event_type_t event_type,
                            const char *data) {
  init_header(event, event_type);
  bpf_probe_read_str(event->path, sizeof(event->path), data);
}

static int send_syscall_pathret(event_type_t event_type, int ret, void *ctx) {
  u64 key = bpf_get_current_pid_tgid();
  struct exit_codepath data = {0};
  init_header(&data, event_type);
  data.ret = ret;

  struct paths *entry_data = path_cache.lookup(&key);
  if (entry_data) {
    bpf_probe_read_str(data.path, sizeof(data.path), entry_data->source);
  }

  path_cache.delete(&key);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

static int send_syscall_pathret2(event_type_t event_type, int ret, void *ctx) {
  u64 key = bpf_get_current_pid_tgid();

  struct exit_codepath2 data = {0};
  init_header(&data, event_type);
  data.ret = ret;

  struct paths *entry_data = path_cache.lookup(&key);
  if (entry_data) {
    bpf_probe_read_str(data.source, sizeof(data.source), entry_data->source);
    bpf_probe_read_str(data.target, sizeof(data.target), entry_data->target);
  }

  path_cache.delete(&key);
  events.perf_submit(ctx, &data, sizeof(data));
  return 0;
}

static int send_syscall_ret(event_type_t event_type, int ret, void *ctx) {
  struct exit_code code = {0};
  init_header(&code, event_type);
  code.ret = ret;
  events.perf_submit(ctx, &code, sizeof(code));
  return 0;
}

static int send_descriptor_event(event_type_t event_type, int fd, void *ctx) {
  struct descriptor_event event = {0};
  init_header(&event, event_type);
  event.fd = fd;
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(sched, sched_process_exit) {
  struct exit_event data = {0};
  init_header(&data, EXIT_EVENT);
  events.perf_submit(args, &data, sizeof(data));
  return 0;
}

#ifdef ENABLE_SCHED_PROCESS_FORK
TRACEPOINT_PROBE(sched, sched_process_fork) {
  return send_syscall_ret(FORK_RET, args->child_pid, args);
}
#endif

static int send_arg(void *ctx, void *ptr, struct path_event *arg) {
  if (!ptr) {
    return -1;
  }

  const char *argp = NULL;
  int ret = bpf_probe_read(&argp, sizeof(argp), ptr);
  if (!argp || ret < 0) {
    return -1;
  }

  init_path_event(arg, EXECVE_ARG, argp);
  events.perf_submit(ctx, arg, sizeof(*arg));
  return 0;
}

// BPF_PERCPU_ARRAY(path_cache, struct execve_path, 1);
// BPF_PERCPU_ARRAY(path_cache, u64, 1);
static int handle_execve(void *args, const char *filename,
                         const char *const *argv, int fd) {
  struct execve_path path_data = {0};
  init_header(&path_data, EXECVE_PATH);
  bpf_probe_read_str(path_data.path, sizeof(path_data.path), filename);
  path_data.fd = fd;

  events.perf_submit(args, &path_data, sizeof(path_data));

  struct path_event arg = {0};
  init_header(&arg, EXECVE_ARG);
#pragma unroll
  for (int i = 0; i < MAXARG; i++) {
    if (send_arg(args, (void *)&argv[i], &arg) < 0) {
      // since the loop has to be unrolled
      // jump will significantly speed the probe in case of smaler argument
      // count
      goto end;
    }
  }

  // handle truncated argument list
  char error[] = "[too many arguments]";
  send_arg(args, (void *)error, &arg);

end:
  return 0;
}

#ifdef ENABLE_EXECVE_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
  return handle_execve(args, args->filename, args->argv, AT_FDCWD);
}

TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
  return send_syscall_ret(EXECVE_RET, args->ret, args);
}
#endif

#ifdef ENABLE_EXECVEAT_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
  return handle_execve(args, args->filename, args->argv, args->fd);
}

TRACEPOINT_PROBE(syscalls, sys_exit_execveat) {
  return send_syscall_ret(EXECVE_RET, args->ret, args);
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_chdir) {
  save_path(args->filename);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chdir) {
  return send_syscall_pathret(CHDIR_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchdir) {
  return send_descriptor_event(FCHDIR_ENTER, args->fd, args);
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchdir) {
  return send_syscall_ret(FCHDIR_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_open) {
  struct openat_enter event = {0};
  init_header(&event, OPEN_ENTER);
  event.dirfd = AT_FDCWD;
  event.flags = args->flags;
  event.mode = args->mode;

  save_path(args->filename);
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_open) {
  return send_syscall_pathret(OPEN_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
  struct openat_enter event = {0};
  init_header(&event, OPENAT_ENTER);
  event.dirfd = args->dfd;
  event.flags = args->flags;
  event.mode = args->mode;
  save_path(args->filename);
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_openat) {
  return send_syscall_pathret(OPENAT_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_creat) {
  struct openat_enter event = {0};
  init_header(&event, CREAT_ENTER);
  event.mode = args->mode;

  save_path(args->pathname);
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_creat) {
  return send_syscall_pathret(CREAT_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_close) {
  return send_descriptor_event(CLOSE_ENTER, args->fd, args);
}

TRACEPOINT_PROBE(syscalls, sys_exit_close) {
  return send_syscall_ret(CLOSE_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlink) {
  struct unlinkat_enter event = {0};
  init_header(&event, UNLINKAT_ENTER);
  save_path(args->pathname);
  event.dirfd = AT_FDCWD;
  event.flags = 0;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlink) {
  return send_syscall_pathret(UNLINK_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_unlinkat) {
  struct unlinkat_enter event = {0};
  init_header(&event, UNLINKAT_ENTER);
  save_path(args->pathname);
  event.dirfd = args->dfd;
  event.flags = args->flag;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unlinkat) {
  return send_syscall_pathret(UNLINKAT_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_rename) {
  struct renameat_enter event = {0};
  init_header(&event, RENAMEAT2_ENTER);
  save_paths(args->oldname, args->newname);
  event.olddirfd = AT_FDCWD;
  event.newdirfd = AT_FDCWD;
  event.flags = 0;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_rename) {
  return send_syscall_pathret2(RENAME_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat) {
  struct renameat_enter event = {0};
  init_header(&event, RENAMEAT2_ENTER);
  save_paths(args->oldname, args->newname);
  event.olddirfd = args->olddfd;
  event.newdirfd = args->newdfd;
  event.flags = 0;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat) {
  return send_syscall_pathret2(RENAMEAT_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_renameat2) {
  struct renameat_enter event = {0};
  init_header(&event, RENAMEAT2_ENTER);
  save_paths(args->oldname, args->newname);
  event.olddirfd = args->olddfd;
  event.newdirfd = args->newdfd;
  event.flags = args->flags;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_renameat2) {
  return send_syscall_pathret2(RENAMEAT2_RET, args->ret, args);
}

#ifdef ENABLE_FORK_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_fork) { return 0; }

TRACEPOINT_PROBE(syscalls, sys_exit_fork) {
  return send_syscall_ret(FORK_RET, args->ret, args);
}
#endif

#ifdef ENABLE_VFORK_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_vfork) { return 0; }

TRACEPOINT_PROBE(syscalls, sys_exit_vfork) {
  return send_syscall_ret(VFORK_RET, args->ret, args);
}
#endif

static int send_clone_enter(void *ctx, int flags) {
  struct clone_enter event = {0};
  init_header(&event, CLONE_ENTER);
  event.clone_flags = flags;
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

#ifdef ENABLE_CLONE_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_clone) {
  return send_clone_enter(args, args->clone_flags);
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone) {
  return send_syscall_ret(CLONE_RET, args->ret, args);
}
#endif

#if defined(ENABLE_CLONE3_TRACEPOINT) || defined(ENABLE_CLONE3_KPROBE)
static int send_clone3_enter(void *ctx, struct clone_args *uargs, size_t size) {
  struct clone_enter event = {0};
  struct clone_args arguments = {0};
  init_header(&event, CLONE3_ENTER);
  bpf_probe_read(&arguments, sizeof(arguments), uargs);
  event.clone_flags = arguments.flags;
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}
#endif

#ifdef ENABLE_CLONE3_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_clone3) {
  return send_clone3_enter(args, args->uargs, args->size);
}

TRACEPOINT_PROBE(syscalls, sys_exit_clone3) {
  return send_syscall_ret(CLONE3_RET, args->ret, args);
}
#endif

#ifdef ENABLE_UNSHARE_TRACEPOINT
TRACEPOINT_PROBE(syscalls, sys_enter_unshare) {
  struct unshare_enter event = {0};
  init_header(&event, UNSHARE_ENTER);
  event.flags = args->unshare_flags;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_unshare) {
  return send_syscall_ret(UNSHARE_RET, args->ret, args);
}
#endif

TRACEPOINT_PROBE(syscalls, sys_enter_fcntl) {
  struct fcntl_enter event = {0};
  init_header(&event, FCNTL_ENTER);
  event.fd = args->fd;
  event.cmd = args->cmd;
  event.arg = args->arg;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fcntl) {
  return send_syscall_ret(FCNTL_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_ioctl) {
  struct fcntl_enter event = {0};
  init_header(&event, IOCTL_ENTER);
  event.fd = args->fd;
  event.cmd = args->cmd;
  event.arg = args->arg;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_ioctl) {
  return send_syscall_ret(IOCTL_RET, args->ret, args);
}

static int send_dup(void *ctx, event_type_t type, int oldfd, int newfd,
                    int flags) {
  struct dup3_enter event = {0};
  init_header(&event, type);
  event.oldfd = oldfd;
  event.newfd = newfd;
  event.flags = flags;
  events.perf_submit(ctx, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup) {
  return send_dup(args, DUP_ENTER, args->fildes, 0, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup) {
  return send_syscall_ret(DUP_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup2) {
  return send_dup(args, DUP2_ENTER, args->oldfd, args->newfd, 0);
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup2) {
  return send_syscall_ret(DUP2_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_dup3) {
  return send_dup(args, DUP3_ENTER, args->oldfd, args->newfd, args->flags);
}

TRACEPOINT_PROBE(syscalls, sys_exit_dup3) {
  return send_syscall_ret(DUP3_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_chmod) {
  struct fchmodat_enter event = {0};
  init_header(&event, CHMOD_ENTER);
  event.dfd = AT_FDCWD;
  bpf_probe_read_str(event.filename, sizeof(event.filename), args->filename);
  event.mode = args->mode;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chmod) {
  return send_syscall_ret(CHMOD_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmod) {
  struct fchmod_enter event = {0};
  init_header(&event, FCHMOD_ENTER);
  event.fd = args->fd;
  event.mode = args->mode;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmod) {
  return send_syscall_ret(FCHMOD_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_fchmodat) {
  struct fchmodat_enter event = {0};
  init_header(&event, FCHMODAT_ENTER);
  event.dfd = AT_FDCWD;
  bpf_probe_read_str(event.filename, sizeof(event.filename), args->filename);
  event.mode = args->mode;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_fchmodat) {
  return send_syscall_ret(FCHMODAT_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_memfd_create) {
  struct memfd_create_enter event = {0};
  init_header(&event, MEMFD_CREATE_ENTER);
  event.flags = args->flags;
  bpf_probe_read_str(event.name, sizeof(event.name), args->uname);
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_memfd_create) {
  return send_syscall_ret(MEMFD_CREATE_RET, args->ret, args);
}

TRACEPOINT_PROBE(syscalls, sys_enter_chroot) {
  struct path_event path_data = {0};
  init_path_event(&path_data, CHROOT_ENTER, args->filename);
  events.perf_submit(args, &path_data, sizeof(path_data));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_chroot) {
  return send_syscall_ret(CHROOT_RET, args->ret, args);
}



static int monitored_sockfamily(void *addr) {
  struct sockaddr *ptr = (struct sockaddr *)addr;
  if (ptr->sa_family != AF_INET && ptr->sa_family != AF_INET6) {
    return 0;
  }

  return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
  u64 pid = getkpid();
  struct tcp_event event = {0};
  init_header(&event, CONNECT_RET);
  event.fd = args->fd;
  event.addrlen = args->addrlen;
  bpf_probe_read(event.sockaddr, sizeof(event.sockaddr), args->uservaddr);

  if (!monitored_sockfamily(event.sockaddr)) {
    return 0;
  }

  connect_cache.insert(&pid, &event);
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_connect) {
  u64 pid = getkpid();
  struct tcp_event *ptr = connect_cache.lookup(&pid);
  if (!ptr) {
    return 0;
  }

  ptr->ret = args->ret;
  events.perf_submit(args, ptr, sizeof(*ptr));
  connect_cache.delete(&pid);
  return 0;
}

static int enter_accept(void *ctx, int fd, void *sockaddr, int *addrlen) {
  u64 pid = getkpid();
  struct accept_data tmp = {0};
  tmp.sockaddr = sockaddr;
  tmp.len = addrlen;
  tmp.fd = fd;
  accept_cache.insert(&pid, &tmp);
  return 0;
}

static int exit_accept(void *ctx, int ret) {
  u64 pid = getkpid();
  struct accept_data *ptr = accept_cache.lookup(&pid);
  if (!ptr) {
    return 0;
  }

  struct tcp_event event = {0};
  init_header(&event, ACCEPT_RET);
  event.fd = ptr->fd;
  bpf_probe_read(&event.addrlen, sizeof(event.addrlen), ptr->len);
  bpf_probe_read(event.sockaddr, sizeof(event.sockaddr), ptr->sockaddr);
  event.ret = ret;

  accept_cache.delete(&pid);

  if (monitored_sockfamily(event.sockaddr)) {
    events.perf_submit(ctx, &event, sizeof(event));
  }

  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept) {
  return enter_accept(args, args->fd, args->upeer_sockaddr,
                      args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept) {
  return exit_accept(args, args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_accept4) {
  return enter_accept(args, args->fd, args->upeer_sockaddr,
                      args->upeer_addrlen);
}

TRACEPOINT_PROBE(syscalls, sys_exit_accept4) {
  return exit_accept(args, args->ret);
}

TRACEPOINT_PROBE(syscalls, sys_enter_kill) {
  struct kill_enter event = {0};
  init_header(&event, KILL_ENTER);
  event.target = args->pid;
  event.signal = args->sig;
  events.perf_submit(args, &event, sizeof(event));
  return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_kill) {
  return send_syscall_ret(KILL_RET, args->ret, args);
}

#ifdef ENABLE_FORK_KPROBE
int syscall__fork_enter(struct pt_regs *ctx) { return 0; }

int syscall__fork_exit(struct pt_regs *ctx) {
  return send_syscall_ret(FORK_RET, PT_REGS_RC(ctx), ctx);
}
#endif

#ifdef ENABLE_VFORK_KPROBE
int syscall__vfork_enter(struct pt_regs *ctx) { return 0; }

int syscall__vfork_exit(struct pt_regs *ctx) {
  return send_syscall_ret(FORK_RET, PT_REGS_RC(ctx), ctx);
}
#endif

#ifdef ENABLE_CLONE_KPROBE
int syscall__clone_enter(struct pt_regs *ctx, void *fn, void *stack, int flags,
                         void *arg) {
  return send_clone_enter(ctx, flags);
}

int syscall__clone_exit(struct pt_regs *ctx, void *fn, void *stack, int flags,
                        void *arg) {
  return send_syscall_ret(CLONE_RET, PT_REGS_RC(ctx), ctx);
}
#endif

#ifdef ENABLE_CLONE3_KPROBE
int syscall__clone3_enter(struct pt_regs *ctx, struct clone_args *cl_args,
                          size_t size) {
  return send_clone3_enter(ctx, cl_args, size);
}

int syscall__clone3_exit(struct pt_regs *ctx, struct clone_args *cl_args,
                         size_t size) {
  return send_syscall_ret(CLONE3_RET, PT_REGS_RC(ctx), ctx);
}
#endif

#ifdef ENABLE_EXECVE_KPROBE
int syscall__execve_enter(struct pt_regs *ctx, const char *pathname, void *argv,
                          void *envp) {
  return handle_execve(ctx, pathname, argv, AT_FDCWD);
}

int syscall__execve_exit(struct pt_regs *ctx, const char *pathname, void *argv,
                         void *envp) {
  return send_syscall_ret(EXECVE_RET, PT_REGS_RC(ctx), ctx);
}
#endif

#ifdef ENABLE_EXECVEAT_KPROBE
int syscall__execveat_enter(struct pt_regs *ctx, int dirfd, void *pathname,
                            void *argv, void *envp, int flags) {
  return handle_execve(ctx, pathname, argv, dirfd);
}

int syscall__execveat_exit(struct pt_regs *ctx, int dirfd, void *pathname,
                           void *argv, void *envp, int flags) {
  return send_syscall_ret(EXECVE_RET, PT_REGS_RC(ctx), ctx);
}
#endif
