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

#define MAXARGSIZE 128
#define MAXPATH 128
#define MAXARG 32
#define MAX_SOCKADDR 28 // sockaddr_in6

enum EVENT_TYPE {
  //***********************************
  // PROCESS EVENTS
  //***********************************
  FORK_EVENT = 0,
  EXEC_TRACE_EVENT,
  EXIT_EVENT,

  EXECVE_ARG,
  EXECVE_PATH,
  EXECVE_RET,

  CLONE_ENTER,
  CLONE_RET,

  CLONE3_ENTER,
  CLONE3_RET,

  FORK_ENTER,
  FORK_RET,

  VFORK_ENTER,
  VFORK_RET,

  UNSHARE_ENTER,
  UNSHARE_RET,

  //***********************************
  // FILE EVENTS
  //***********************************

  OPEN_ENTER,
  OPEN_RET,

  OPENAT_ENTER,
  OPENAT_RET,

  CREAT_ENTER,
  CREAT_RET,

  CHMOD_ENTER,
  CHMOD_RET,

  FCHMOD_ENTER,
  FCHMOD_RET,

  FCHMODAT_ENTER,
  FCHMODAT_RET,

  UNLINK_ENTER,
  UNLINK_RET,

  UNLINKAT_ENTER,
  UNLINKAT_RET,

  RENAME_ENTER,
  RENAME_RET,

  RENAMEAT_ENTER,
  RENAMEAT_RET,

  RENAMEAT2_ENTER,
  RENAMEAT2_RET,

  IOCTL_ENTER,
  IOCTL_RET,

  //***********************************
  // CWD EVENTS
  //***********************************

  CHDIR_ENTER,
  CHDIR_RET,

  FCHDIR_ENTER,
  FCHDIR_RET,

  CHROOT_ENTER,
  CHROOT_RET,

  //***********************************
  // DESCRIPTOR EVENTS
  //***********************************

  FCNTL_ENTER,
  FCNTL_RET,

  DUP_ENTER,
  DUP_RET,

  DUP2_ENTER,
  DUP2_RET,

  DUP3_ENTER,
  DUP3_RET,

  MEMFD_CREATE_ENTER,
  MEMFD_CREATE_RET,

  CLOSE_ENTER,
  CLOSE_RET,

  //***********************************
  // NETWORK EVENTS
  //***********************************

  CONNECT_ENTER,
  CONNECT_RET,

  ACCEPT_ENTER,
  ACCEPT_RET,

  KILL_ENTER,
  KILL_RET,
};

typedef uint64_t event_type_t;

struct event_header {
  event_type_t event_type;
  uint64_t timestamp;
  uint64_t pid_tgid;
  uint32_t uid;
  uint32_t gid;
} __attribute__((packed));

struct fork_event {
  struct event_header header;
  int32_t child_pid;
} __attribute__((packed));

struct execve_path {
  struct event_header header;
  char path[MAXPATH];
  int32_t fd;
} __attribute__((packed));

struct execve_arg {
  struct event_header header;
  char arg[MAXARGSIZE];
} __attribute__((packed));

struct execve_ret {
  struct event_header header;
  int retval;
} __attribute__((packed));

struct exec_trace {
  struct event_header header;
  char path[MAXPATH];
} __attribute__((packed));

struct exit_event {
  struct event_header header;
} __attribute__((packed));

struct exit_code {
  struct event_header header;
  int32_t ret;
} __attribute__((packed));

struct exit_codepath {
  struct event_header header;
  int32_t ret;
  char path[MAXPATH];
} __attribute__((packed));

struct exit_codepath2 {
  struct event_header header;
  int32_t ret;
  char source[MAXPATH];
  char target[MAXPATH];
} __attribute__((packed));

struct path_event {
  struct event_header header;
  char path[MAXPATH];
} __attribute__((packed));

struct descriptor_event {
  struct event_header header;
  int32_t fd;
} __attribute__((packed));

struct openat_enter {
  struct event_header header;
  int32_t dirfd;
  int32_t flags;
  int32_t mode;
} __attribute__((packed));

struct renameat_enter {
  struct event_header header;
  int32_t olddirfd;
  int32_t newdirfd;
  int32_t flags;
} __attribute__((packed));

struct unlinkat_enter {
  struct event_header header;
  int32_t dirfd;
  int32_t flags;
} __attribute__((packed));

struct clone_enter {
  struct event_header header;
  uint64_t clone_flags;
  uint64_t newsp;
} __attribute__((packed));

struct unshare_enter {
  struct event_header header;
  uint64_t flags;
} __attribute__((packed));

struct fcntl_enter {
  struct event_header header;
  int32_t fd;
  int32_t cmd;
  int64_t arg;
} __attribute__((packed));

struct dup3_enter {
  struct event_header header;
  uint32_t oldfd;
  uint32_t newfd;
  int32_t flags;
} __attribute__((packed));

struct fchmod_enter {
  struct event_header header;
  int32_t fd;
  uint32_t mode;
} __attribute__((packed));

struct fchmodat_enter {
  struct event_header header;
  int32_t dfd;
  char filename[MAXPATH];
  uint32_t mode;
} __attribute__((packed));

struct memfd_create_enter {
  struct event_header header;
  char name[MAXPATH];
  int32_t flags;
} __attribute__((packed));

struct chroot_enter {
  struct event_header header;
  char name[MAXPATH];
} __attribute__((packed));

struct tcp_event {
  struct event_header header;
  uint8_t sockaddr[MAX_SOCKADDR];
  int32_t addrlen; 
  int32_t fd;
  int32_t ret;
} __attribute__((packed));

struct kill_enter {
  struct event_header header;
  pid_t target;
  int32_t signal;
} __attribute__((packed));
