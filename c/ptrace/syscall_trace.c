

// Originally, this program should run on X86-32. I ported it to X86_64 and change corresponding registers. I donot know if this modification is ok.
// use ptrace() to trace syscalls made by a process

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ctype.h>
#include <sys/user.h>
#include <sys/types.h>
#include <unistd.h>

#define X86_64

char *syscall_names[] = {
#ifdef X86_64
// From strace-4.11/linux/x86_64/syscallent.h
	"read",
	"write",
	"open",
	"close",
	"stat",
	"fstat",
	"lstat",
	"poll",
	"lseek",
	"mmap",
	"mprotect",
	"munmap",
	"brk",
	"rt_sigaction",
	"rt_sigprocmask",
	"rt_sigreturn",
	"ioctl",
	"pread64",
	"pwrite64",
	"readv",
	"writev",
	"access",
	"pipe",
	"select",
	"sched_yield",
	"mremap",
	"msync",
	"mincore",
	"madvise",
	"shmget",
	"shmat",
	"shmctl",
	"dup",
	"dup2",
	"pause",
	"nanosleep",
	"getitimer",
	"alarm",
	"setitimer",
	"getpid",
	"sendfile",
	"socket",
	"connect",
	"accept",
	"sendto",
	"recvfrom",
	"sendmsg",
	"recvmsg",
	"shutdown",
	"bind",
	"listen",
	"getsockname",
	"getpeername",
	"socketpair",
	"setsockopt",
	"getsockopt",
	"clone",
	"fork",
	"vfork",
	"execve",
	"exit",
	"wait4",
	"kill",
	"uname",
	"semget",
	"semop",
	"semctl",
	"shmdt",
	"msgget",
	"msgsnd",
	"msgrcv",
	"msgctl",
	"fcntl",
	"flock",
	"fsync",
	"fdatasync",
	"truncate",
	"ftruncate",
	"getdents",
	"getcwd",
	"chdir",
	"fchdir",
	"rename",
	"mkdir",
	"rmdir",
	"creat",
	"link",
	"unlink",
	"symlink",
	"readlink",
	"chmod",
	"fchmod",
	"chown",
	"fchown",
	"lchown",
	"umask",
	"gettimeofday",
	"getrlimit",
	"getrusage",
	"sysinfo",
	"times",
	"ptrace",
	"getuid",
	"syslog",
	"getgid",
	"setuid",
	"setgid",
	"geteuid",
	"getegid",
	"setpgid",
	"getppid",
	"getpgrp",
	"setsid",
	"setreuid",
	"setregid",
	"getgroups",
	"setgroups",
	"setresuid",
	"getresuid",
	"setresgid",
	"getresgid",
	"getpgid",
	"setfsuid",
	"setfsgid",
	"getsid",
	"capget",
	"capset",
	"rt_sigpending",
	"rt_sigtimedwait",
	"rt_sigqueueinfo",
	"rt_sigsuspend",
	"sigaltstack",
	"utime",
	"mknod",
	"uselib",
	"personality",
	"ustat",
	"statfs",
	"fstatfs",
	"sysfs",
	"getpriority",
	"setpriority",
	"sched_setparam",
	"sched_getparam",
	"sched_setscheduler",
	"sched_getscheduler",
	"sched_get_priority_max",
	"sched_get_priority_min",
	"sched_rr_get_interval",
	"mlock",
	"munlock",
	"mlockall",
	"munlockall",
	"vhangup",
	"modify_ldt",
	"pivot_root",
	"_sysctl",
	"prctl",
	"arch_prctl",
	"adjtimex",
	"setrlimit",
	"chroot",
	"sync",
	"acct",
	"settimeofday",
	"mount",
	"umount2",
	"swapon",
	"swapoff",
	"reboot",
	"sethostname",
	"setdomainname",
	"iopl",
	"ioperm",
	"create_module",
	"init_module",
	"delete_module",
	"get_kernel_syms",
	"query_module",
	"quotactl",
	"nfsservctl",
	"getpmsg",
	"putpmsg",
	"afs_syscall",
	"tuxcall",
	"security",
	"gettid",
	"readahead",
	"setxattr",
	"lsetxattr",
	"fsetxattr",
	"getxattr",
	"lgetxattr",
	"fgetxattr",
	"listxattr",
	"llistxattr",
	"flistxattr",
	"removexattr",
	"lremovexattr",
	"fremovexattr",
	"tkill",
	"time",
	"futex",
	"sched_setaffinity",
	"sched_getaffinity",
	"set_thread_area",
	"io_setup",
	"io_destroy",
	"io_getevents",
	"io_submit",
	"io_cancel",
	"get_thread_area",
	"lookup_dcookie",
	"epoll_create",
	"epoll_ctl_old",
	"epoll_wait_old",
	"remap_file_pages",
	"getdents64",
	"set_tid_address",
	"restart_syscall",
	"semtimedop",
	"fadvise64",
	"timer_create",
	"timer_settime",
	"timer_gettime",
	"timer_getoverrun",
	"timer_delete",
	"clock_settime",
	"clock_gettime",
	"clock_getres",
	"clock_nanosleep",
	"exit_group",
	"epoll_wait",
	"epoll_ctl",
	"tgkill",
	"utimes",
	"vserver",
	"mbind",
	"set_mempolicy",
	"get_mempolicy",
	"mq_open",
	"mq_unlink",
	"mq_timedsend",
	"mq_timedreceive",
	"mq_notify",
	"mq_getsetattr",
	"kexec_load",
	"waitid",
	"add_key",
	"request_key",
	"keyctl",
	"ioprio_set",
	"ioprio_get",
	"inotify_init",
	"inotify_add_watch",
	"inotify_rm_watch",
	"migrate_pages",
	"openat",
	"mkdirat",
	"mknodat",
	"fchownat",
	"futimesat",
	"newfstatat",
	"unlinkat",
	"renameat",
	"linkat",
	"symlinkat",
	"readlinkat",
	"fchmodat",
	"faccessat",
	"pselect6",
	"ppoll",
	"unshare",
	"set_robust_list",
	"get_robust_list",
	"splice",
	"tee",
	"sync_file_range",
	"vmsplice",
	"move_pages",
	"utimensat",
	"epoll_pwait",
	"signalfd",
	"timerfd_create",
	"eventfd",
	"fallocate",
	"timerfd_settime",
	"timerfd_gettime",
	"accept4",
	"signalfd4",
	"eventfd2",
	"epoll_create1",
	"dup3",
	"pipe2",
	"inotify_init1",
	"preadv",
	"pwritev",
	"rt_tgsigqueueinfo",
	"perf_event_open",
	"recvmmsg",
	"fanotify_init",
	"fanotify_mark",
	"prlimit64",
	"name_to_handle_at",
	"open_by_handle_at",
	"clock_adjtime",
	"syncfs",
	"sendmmsg",
	"setns",
	"getcpu",
	"process_vm_readv",
	"process_vm_writev",
	"kcmp",
	"finit_module",
	"sched_setattr",
	"sched_getattr",
	"renameat2",
	"seccomp",
	"getrandom",
	"memfd_create",
	"kexec_file_load",
	"bpf",
	"execveat",
	"userfaultfd",
	"membarrier",
	"mlock2"
#else
	"",
	"exit", /* 1 */
	"fork", /* 2 */
	"read", /* 3 */
	"write", /* 4 */
	"open", /* 5 */
	"close", /* 6 */
	"waitpid", /* 7 */
	"creat", /* 8 */
	"link", /* 9 */
	"unlink", /* 10 */
	"execve", /* 11 */
	"chdir", /* 12 */
	"time", /* 13 */
	"mknod", /* 14 */
	"chmod", /* 15 */
	"lchown", /* 16 */
	"break", /* 17 */
	"oldstat", /* 18 */
	"lseek", /* 19 */
	"getpid", /* 20 */
	"mount", /* 21 */
	"umount", /* 22 */
	"setuid", /* 23 */
	"getuid", /* 24 */
	"stime", /* 25 */
	"ptrace", /* 26 */
	"alarm", /* 27 */
	"oldfstat", /* 28 */
	"pause", /* 29 */
	"utime", /* 30 */
	"stty", /* 31 */
	"gtty", /* 32 */
	"access", /* 33 */
	"nice", /* 34 */
	"ftime", /* 35 */
	"sync", /* 36 */
	"kill", /* 37 */
	"rename", /* 38 */
	"mkdir", /* 39 */
	"rmdir", /* 40 */
	"dup", /* 41 */
	"pipe", /* 42 */
	"times", /* 43 */
	"prof", /* 44 */
	"brk", /* 45 */
	"setgid", /* 46 */
	"getgid", /* 47 */
	"signal", /* 48 */
	"geteuid", /* 49 */
	"getegid", /* 50 */
	"acct", /* 51 */
	"umount2", /* 52 */
	"lock", /* 53 */
	"ioctl", /* 54 */
	"fcntl", /* 55 */
	"mpx", /* 56 */
	"setpgid", /* 57 */
	"ulimit", /* 58 */
	"oldolduname", /* 59 */
	"umask", /* 60 */
	"chroot", /* 61 */
	"ustat", /* 62 */
	"dup2", /* 63 */
	"getppid", /* 64 */
	"getpgrp", /* 65 */
	"setsid", /* 66 */
	"sigaction", /* 67 */
	"sgetmask", /* 68 */
	"ssetmask", /* 69 */
	"setreuid", /* 70 */
	"setregid", /* 71 */
	"sigsuspend", /* 72 */
	"sigpending", /* 73 */
	"sethostname", /* 74 */
	"setrlimit", /* 75 */
	"getrlimit", /* 76 */
	"getrusage", /* 77 */
	"gettimeofday", /* 78 */
	"settimeofday", /* 79 */
	"getgroups", /* 80 */
	"setgroups", /* 81 */
	"select", /* 82 */
	"symlink", /* 83 */
	"oldlstat", /* 84 */
	"readlink", /* 85 */
	"uselib", /* 86 */
	"swapon", /* 87 */
	"reboot", /* 88 */
	"readdir", /* 89 */
	"mmap", /* 90 */
	"munmap", /* 91 */
	"truncate", /* 92 */
	"ftruncate", /* 93 */
	"fchmod", /* 94 */
	"fchown", /* 95 */
	"getpriority", /* 96 */
	"setpriority", /* 97 */
	"profil", /* 98 */
	"statfs", /* 99 */
	"fstatfs", /* 100 */
	"ioperm", /* 101 */
	"socketcall", /* 102 */
	"syslog", /* 103 */
	"setitimer", /* 104 */
	"getitimer", /* 105 */
	"stat", /* 106 */
	"lstat", /* 107 */
	"fstat", /* 108 */
	"olduname", /* 109 */
	"iopl", /* 110 */
	"vhangup", /* 111 */
	"idle", /* 112 */
	"vm86old", /* 113 */
	"wait4", /* 114 */
	"swapoff", /* 115 */
	"sysinfo", /* 116 */
	"ipc", /* 117 */
	"fsync", /* 118 */
	"sigreturn", /* 119 */
	"clone", /* 120 */
	"setdomainname", /* 121 */
	"uname", /* 122 */
	"modify_ldt", /* 123 */
	"adjtimex", /* 124 */
	"mprotect", /* 125 */
	"sigprocmask", /* 126 */
	"create_module", /* 127 */
	"init_module", /* 128 */
	"delete_module", /* 129 */
	"get_kernel_syms", /* 130 */
	"quotactl", /* 131 */
	"getpgid", /* 132 */
	"fchdir", /* 133 */
	"bdflush", /* 134 */
	"sysfs", /* 135 */
	"personality", /* 136 */
	"afs_syscall", /* 137 */
	"setfsuid", /* 138 */
	"setfsgid", /* 139 */
	"_llseek", /* 140 */
	"getdents", /* 141 */
	"_newselect", /* 142 */
	"flock", /* 143 */
	"msync", /* 144 */
	"readv", /* 145 */
	"writev", /* 146 */
	"getsid", /* 147 */
	"fdatasync", /* 148 */
	"_sysctl", /* 149 */
	"mlock", /* 150 */
	"munlock", /* 151 */
	"mlockall", /* 152 */
	"munlockall", /* 153 */
	"sched_setparam", /* 154 */
	"sched_getparam", /* 155 */
	"sched_setscheduler", /* 156 */
	"sched_getscheduler", /* 157 */
	"sched_yield", /* 158 */
	"sched_get_priority_max", /* 159 */
	"sched_get_priority_min", /* 160 */
	"sched_rr_get_interval", /* 161 */
	"nanosleep", /* 162 */
	"mremap", /* 163 */
	"setresuid", /* 164 */
	"getresuid", /* 165 */
	"vm86", /* 166 */
	"query_module", /* 167 */
	"poll", /* 168 */
	"nfsservctl", /* 169 */
	"setresgid", /* 170 */
	"getresgid", /* 171 */
	"prctl", /* 172 */
	"rt_sigreturn", /* 173 */
	"rt_sigaction", /* 174 */
	"rt_sigprocmask", /* 175 */
	"rt_sigpending", /* 176 */
	"rt_sigtimedwait", /* 177 */
	"rt_sigqueueinfo", /* 178 */
	"rt_sigsuspend", /* 179 */
	"pread", /* 180 */
	"pwrite", /* 181 */
	"chown", /* 182 */
	"getcwd", /* 183 */
	"capget", /* 184 */
	"capset", /* 185 */
	"sigaltstack", /* 186 */
	"sendfile", /* 187 */
	"getpmsg", /* 188 */
	"putpmsg", /* 189 */
	"vfork", /* 190 */
	"ugetrlimit", /* 191 */
	"mmap2", /* 192 */
	"truncate64", /* 193 */
	"ftruncate64", /* 194 */
	"stat64", /* 195 */
	"lstat64", /* 196 */
	"fstat64", /* 197 */
	"lchown32", /* 198 */
	"getuid32", /* 199 */
	"getgid32", /* 200 */
	"geteuid32", /* 201 */
	"getegid32", /* 202 */
	"setreuid32", /* 203 */
	"setregid32", /* 204 */
	"getgroups32", /* 205 */
	"setgroups32", /* 206 */
	"fchown32", /* 207 */
	"setresuid32", /* 208 */
	"getresuid32", /* 209 */
	"setresgid32", /* 210 */
	"getresgid32", /* 211 */
	"chown32", /* 212 */
	"setuid32", /* 213 */
	"setgid32", /* 214 */
	"setfsuid32", /* 215 */
	"setfsgid32", /* 216 */
	"pivot_root", /* 217 */
	"mincore", /* 218 */
	"madvise", /* 219 */
	"madvise1", /* 220 */
	"getdents64", /* 221 */
	"fcntl64", /* 222 */
	"security", /* 223 */
	"gettid", /* 224 */
	"readahead", /* 225 */
	"setxattr", /* 226 */
	"lsetxattr", /* 227 */
	"fsetxattr", /* 228 */
	"getxattr", /* 229 */
	"lgetxattr", /* 230 */
	"fgetxattr", /* 231 */
	"listxattr", /* 232 */
	"llistxattr", /* 233 */
	"flistxattr", /* 234 */
	"removexattr", /* 235 */
	"lremovexattr", /* 236 */
	"fremovexattr" /* 237 */
#endif
};

void printregs(struct user_regs_struct *regs) {
#define PRINTREG(regname) printf("%9s: 0x%08lx ", #regname, regs->regname);
#define PRINTREG2(regname) printf("%9s: 0x%08x ", #regname, regs->regname);
#ifdef X86_64
	PRINTREG(rax);
	PRINTREG(rbx);
	PRINTREG(rcx);
	PRINTREG(rdx);
	puts("");
#else
	PRINTREG(eax);
	PRINTREG(ebx);
	PRINTREG(ecx);
	PRINTREG(edx);
	puts("");
	PRINTREG(esi);
	PRINTREG(edi);
	PRINTREG(ebp);
	puts("");
	PRINTREG2(ds);
	PRINTREG2(__ds);
	PRINTREG2(es);
	PRINTREG2(__es);
	puts("");
	PRINTREG2(fs);
	PRINTREG2(__fs);
	PRINTREG2(gs);
	PRINTREG2(__gs);
	puts("");
	PRINTREG(orig_eax);
	PRINTREG(eip);
	PRINTREG2(cs);
	PRINTREG2(__cs);
	puts("");
	PRINTREG(eflags);
	PRINTREG(esp);
	PRINTREG2(ss);
	PRINTREG2(__ss);
	puts("");
#endif
#undef PRINTREG
#undef PRINTREG2
}	

int do_forkexec(char **argv, char **envp) {
	int pid;
	pid = fork();
	switch(pid) {
	case -1:
		assert(0);
	case 0:
		ptrace(PTRACE_TRACEME, 0,0,0);
		execve(argv[0], argv, envp);
		assert(0);
	default:
		return pid;
	}
}


void print_memory(char *filename, int pid, void *addr, unsigned long len) {
  FILE *fp;
  int r;
  fp = fopen(filename, "w");
  assert(fp);
  
  while (len > 0) {
  r = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
  fwrite(&r, sizeof(int), 1, fp);
  addr += 4;
  len -= 4;
  }
  fclose(fp);
}
int main(int argc, char **argv, char **envp) {
	int pid, r, count, c;
//	char buf[4];
	struct user_regs_struct regs;
	char *pid_arg=NULL;

	while ((c = getopt (argc, argv, "p:")) != -1) {
		switch (c)
		{
			case 'p':
				pid_arg = optarg;
				break;
			default:
				puts("Unknown parameters!");
		}
	}

	if(pid_arg) {
		char *ptr=pid_arg;
		while(*ptr) {
			assert(isdigit(*ptr));
			ptr++;
		}
		pid = atoi(pid_arg);
		printf("Attaching to pid %d\n", pid);
	} else {
		argv++;
		pid = do_forkexec(argv, envp);
	}
	
	r = ptrace(PTRACE_ATTACH, pid, 0, 0);
	assert(!r);

	count = 0;
	for(;;) {
		wait(0);
		r = ptrace(PTRACE_GETREGS, pid, 0, &regs);
		if (r)
			break;

#ifdef X86_64
		assert(regs.orig_rax >= 0);
		assert(regs.orig_rax < sizeof(syscall_names));
		if(regs.rax != -38) {
			printf("%d %s(%ld) = %ld;\n",
			       count,
			       syscall_names[regs.orig_rax],
			       regs.rdi,
			       regs.rax);
#else
		assert(regs.orig_eax > 0);
		assert(regs.orig_eax < sizeof(syscall_names));
		if(regs.eax != -38) {
			printf("%d %s(%ld) = %ld;\n",
			       count,
			       syscall_names[regs.orig_eax],
			       regs.ebx,
			       regs.eax);
#endif
			count++;
			fflush(stdout);
//			if (count == 4) {
//			  print_memory("mem", pid, (void*)0x08048114L -  1024*10, 0x080495e0L - 0x08048114L + 1024*64);
//			  break;
//			}
		}
//		printregs(&regs);
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
	}
	ptrace(PTRACE_CONT, pid, 0, 0);
	ptrace(PTRACE_DETACH, pid, 0, 0);

	return 0;
}



