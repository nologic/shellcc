
    static int scc_nosys(void) {
        return scc_syscall0(0);
    }
    

    static void scc_exit(int rval) {
        scc_syscall1((uint64_t)rval, 1);
        __builtin_unreachable ();
    }
    

    static int scc_fork(void) {
        return scc_syscall0(2);
    }
    

    static int scc_read(int fd, char* cbuf, user_size_t nbyte) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, 3);
    }
    

    static int scc_write(int fd, char* cbuf, user_size_t nbyte) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, 4);
    }
    

    static int scc_open(char* path, int flags, int mode) {
        return scc_syscall3((uint64_t)path, (uint64_t)flags, (uint64_t)mode, 5);
    }
    

    static int scc_close(int fd) {
        return scc_syscall1((uint64_t)fd, 6);
    }
    

    static int scc_wait4(int pid, user_addr_t status, int options, user_addr_t rusage) {
        return scc_syscall4((uint64_t)pid, (uint64_t)status, (uint64_t)options, (uint64_t)rusage, 7);
    }
    

    static int scc_link(char* path, user_addr_t link) {
        return scc_syscall2((uint64_t)path, (uint64_t)link, 9);
    }
    

    static int scc_unlink(char* path) {
        return scc_syscall1((uint64_t)path, 10);
    }
    

    static int scc_chdir(char* path) {
        return scc_syscall1((uint64_t)path, 12);
    }
    

    static int scc_fchdir(int fd) {
        return scc_syscall1((uint64_t)fd, 13);
    }
    

    static int scc_mknod(char* path, int mode, int dev) {
        return scc_syscall3((uint64_t)path, (uint64_t)mode, (uint64_t)dev, 14);
    }
    

    static int scc_chmod(char* path, int mode) {
        return scc_syscall2((uint64_t)path, (uint64_t)mode, 15);
    }
    

    static int scc_chown(char* path, int uid, int gid) {
        return scc_syscall3((uint64_t)path, (uint64_t)uid, (uint64_t)gid, 16);
    }
    

    static int scc_getfsstat(char* buf, int bufsize, int flags) {
        return scc_syscall3((uint64_t)buf, (uint64_t)bufsize, (uint64_t)flags, 18);
    }
    

    static int scc_getpid(void) {
        return scc_syscall0(20);
    }
    

    static int scc_setuid(uid_t uid) {
        return scc_syscall1((uint64_t)uid, 23);
    }
    

    static int scc_getuid(void) {
        return scc_syscall0(24);
    }
    

    static int scc_geteuid(void) {
        return scc_syscall0(25);
    }
    

    static int scc_ptrace(int req, pid_t pid, caddr_t addr, int data) {
        return scc_syscall4((uint64_t)req, (uint64_t)pid, (uint64_t)addr, (uint64_t)data, 26);
    }
    

    static int scc_recvmsg(int s, struct msghdr *msg, int flags) {
        return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, 27);
    }
    

    static int scc_sendmsg(int s, caddr_t msg, int flags) {
        return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, 28);
    }
    

    static int scc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) {
        return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)from, (uint64_t)fromlenaddr, 29);
    }
    

    static int scc_accept(int s, caddr_t name, socklen_t *anamelen) {
        return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)anamelen, 30);
    }
    

    static int scc_getpeername(int fdes, caddr_t asa, socklen_t *alen) {
        return scc_syscall3((uint64_t)fdes, (uint64_t)asa, (uint64_t)alen, 31);
    }
    

    static int scc_getsockname(int fdes, caddr_t asa, socklen_t *alen) {
        return scc_syscall3((uint64_t)fdes, (uint64_t)asa, (uint64_t)alen, 32);
    }
    

    static int scc_access(char* path, int flags) {
        return scc_syscall2((uint64_t)path, (uint64_t)flags, 33);
    }
    

    static int scc_chflags(char *path, int flags) {
        return scc_syscall2((uint64_t)path, (uint64_t)flags, 34);
    }
    

    static int scc_fchflags(int fd, int flags) {
        return scc_syscall2((uint64_t)fd, (uint64_t)flags, 35);
    }
    

    static int scc_sync(void) {
        return scc_syscall0(36);
    }
    

    static int scc_kill(int pid, int signum, int posix) {
        return scc_syscall3((uint64_t)pid, (uint64_t)signum, (uint64_t)posix, 37);
    }
    

    static int scc_getppid(void) {
        return scc_syscall0(39);
    }
    
    static int scc_dup(u_int fd) {
        return scc_syscall1((uint64_t)fd, 41);
    }
    

    static int scc_pipe(void) {
        return scc_syscall0(42);
    }
    

    static int scc_getegid(void) {
        return scc_syscall0(43);
    }
    

    static int scc_sigaction(int signum, struct __sigaction *nsa, struct sigaction *osa) {
        return scc_syscall3((uint64_t)signum, (uint64_t)nsa, (uint64_t)osa, 46);
    }
    

    static int scc_getgid(void) {
        return scc_syscall0(47);
    }
    

    static int scc_sigprocmask(int how, user_addr_t mask, user_addr_t omask) {
        return scc_syscall3((uint64_t)how, (uint64_t)mask, (uint64_t)omask, 48);
    }
    

    static int scc_getlogin(char *namebuf, u_int namelen) {
        return scc_syscall2((uint64_t)namebuf, (uint64_t)namelen, 49);
    }
    

    static int scc_setlogin(char *namebuf) {
        return scc_syscall1((uint64_t)namebuf, 50);
    }
    

    static int scc_acct(char *path) {
        return scc_syscall1((uint64_t)path, 51);
    }
    

    static int scc_sigpending(struct sigvec *osv) {
        return scc_syscall1((uint64_t)osv, 52);
    }
    

    static int scc_sigaltstack(const stack_t *restrict nss, stack_t *restrict oss) {
        return scc_syscall2((uint64_t)nss, (uint64_t)oss, 53);
    }
    

    static int scc_ioctl(int fd, u_long com, caddr_t data) {
        return scc_syscall3((uint64_t)fd, (uint64_t)com, (uint64_t)data, 54);
    }
    

    static int scc_reboot(int opt, char *command) {
        return scc_syscall2((uint64_t)opt, (uint64_t)command, 55);
    }
    

    static int scc_revoke(char *path) {
        return scc_syscall1((uint64_t)path, 56);
    }
    

    static int scc_symlink(char *path, char *link) {
        return scc_syscall2((uint64_t)path, (uint64_t)link, 57);
    }
    

    static int scc_readlink(char *path, char *buf, int count) {
        return scc_syscall3((uint64_t)path, (uint64_t)buf, (uint64_t)count, 58);
    }
    

    static int scc_execve(char *fname, char **argp, char **envp) {
        return scc_syscall3((uint64_t)fname, (uint64_t)argp, (uint64_t)envp, 59);
    }
    

    static int scc_umask(int newmask) {
        return scc_syscall1((uint64_t)newmask, 60);
    }
    

    static int scc_chroot(char* path) {
        return scc_syscall1((uint64_t)path, 61);
    }
    
    static int scc_msync(caddr_t addr, size_t len, int flags) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)flags, 65);
    }
    

    static int scc_vfork(void) {
        return scc_syscall0(66);
    }    

    static int scc_munmap(caddr_t addr, size_t len) {
        return scc_syscall2((uint64_t)addr, (uint64_t)len, 73);
    }
    

    static int scc_mprotect(caddr_t addr, size_t len, int prot) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)prot, 74);
    }
    

    static int scc_madvise(caddr_t addr, size_t len, int behav) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)behav, 75);
    }
    
    static int scc_mincore(user_addr_t addr, user_size_t len, user_addr_t vec) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)vec, 78);
    }
    

    static int scc_getgroups(u_int gidsetsize, gid_t *gidset) {
        return scc_syscall2((uint64_t)gidsetsize, (uint64_t)gidset, 79);
    }
    

    static int scc_setgroups(u_int gidsetsize, gid_t *gidset) {
        return scc_syscall2((uint64_t)gidsetsize, (uint64_t)gidset, 80);
    }
    

    static int scc_getpgrp(void) {
        return scc_syscall0(81);
    }
    

    static int scc_setpgid(int pid, int pgid) {
        return scc_syscall2((uint64_t)pid, (uint64_t)pgid, 82);
    }
    

    static int scc_setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv) {
        return scc_syscall3((uint64_t)which, (uint64_t)itv, (uint64_t)oitv, 83);
    }
    

    static int scc_swapon(void) {
        return scc_syscall0(85);
    }
    

    static int scc_getitimer(u_int which, struct itimerval *itv) {
        return scc_syscall2((uint64_t)which, (uint64_t)itv, 86);
    }
    
    static int scc_getdtablesize(void) {
        return scc_syscall0(89);
    }
    

    static int scc_dup2(u_int from, u_int to) {
        return scc_syscall2((uint64_t)from, (uint64_t)to, 90);
    }
    
    static int scc_fcntl(int fd, int cmd, long arg) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cmd, (uint64_t)arg, 92);
    }
    

    static int scc_select(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) {
        return scc_syscall5((uint64_t)nd, (uint64_t)in, (uint64_t)ou, (uint64_t)ex, (uint64_t)tv, 93);
    }
    
    static int scc_fsync(int fd) {
        return scc_syscall1((uint64_t)fd, 95);
    }
    

    static int scc_setpriority(int which, id_t who, int prio) {
        return scc_syscall3((uint64_t)which, (uint64_t)who, (uint64_t)prio, 96);
    }
    

    static int scc_socket(int domain, int type, int protocol) {
        return scc_syscall3((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, 97);
    }
    

    static int scc_connect(int s, caddr_t name, socklen_t namelen) {
        return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, 98);
    }
    
    static int scc_getpriority(int which, id_t who) {
        return scc_syscall2((uint64_t)which, (uint64_t)who, 100);
    }
    
    static int scc_bind(int s, caddr_t name, socklen_t namelen) {
        return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, 104);
    }
    

    static int scc_setsockopt(int s, int level, int name, caddr_t val, socklen_t valsize) {
        return scc_syscall5((uint64_t)s, (uint64_t)level, (uint64_t)name, (uint64_t)val, (uint64_t)valsize, 105);
    }
    

    static int scc_listen(int s, int backlog) {
        return scc_syscall2((uint64_t)s, (uint64_t)backlog, 106);
    }
    
    static int scc_sigsuspend(sigset_t mask) {
        return scc_syscall1((uint64_t)mask, 111);
    }
    
    static int scc_gettimeofday(struct timeval *tp, struct timezone *tzp) {
        return scc_syscall2((uint64_t)tp, (uint64_t)tzp, 116);
    }
    

    static int scc_getrusage(int who, struct rusage *rusage) {
        return scc_syscall2((uint64_t)who, (uint64_t)rusage, 117);
    }
    

    static int scc_getsockopt(int s, int level, int name, caddr_t val, socklen_t *avalsize) {
        return scc_syscall5((uint64_t)s, (uint64_t)level, (uint64_t)name, (uint64_t)val, (uint64_t)avalsize, 118);
    }
    

    static int scc_readv(int fd, struct iovec *iovp, u_int iovcnt) {
        return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, 120);
    }
    

    static int scc_writev(int fd, struct iovec *iovp, u_int iovcnt) {
        return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, 121);
    }
    

    static int scc_settimeofday(struct timeval *tv, struct timezone *tzp) {
        return scc_syscall2((uint64_t)tv, (uint64_t)tzp, 122);
    }
    

    static int scc_fchown(int fd, int uid, int gid) {
        return scc_syscall3((uint64_t)fd, (uint64_t)uid, (uint64_t)gid, 123);
    }
    

    static int scc_fchmod(int fd, int mode) {
        return scc_syscall2((uint64_t)fd, (uint64_t)mode, 124);
    }
    

    static int scc_setreuid(uid_t ruid, uid_t euid) {
        return scc_syscall2((uint64_t)ruid, (uint64_t)euid, 126);
    }
    

    static int scc_setregid(gid_t rgid, gid_t egid) {
        return scc_syscall2((uint64_t)rgid, (uint64_t)egid, 127);
    }
    

    static int scc_rename(char *from, char *to) {
        return scc_syscall2((uint64_t)from, (uint64_t)to, 128);
    }
    
    static int scc_flock(int fd, int how) {
        return scc_syscall2((uint64_t)fd, (uint64_t)how, 131);
    }
    

    static int scc_mkfifo(char* path, int mode) {
        return scc_syscall2((uint64_t)path, (uint64_t)mode, 132);
    }
    

    static int scc_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) {
        return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)to, (uint64_t)tolen, 133);
    }
    

    static int scc_shutdown(int s, int how) {
        return scc_syscall2((uint64_t)s, (uint64_t)how, 134);
    }
    

    static int scc_socketpair(int domain, int type, int protocol, int *rsv) {
        return scc_syscall4((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, (uint64_t)rsv, 135);
    }
    

    static int scc_mkdir(char* path, int mode) {
        return scc_syscall2((uint64_t)path, (uint64_t)mode, 136);
    }
    

    static int scc_rmdir(char *path) {
        return scc_syscall1((uint64_t)path, 137);
    }
    

    static int scc_utimes(char *path, struct timeval *tptr) {
        return scc_syscall2((uint64_t)path, (uint64_t)tptr, 138);
    }
    

    static int scc_futimes(int fd, struct timeval *tptr) {
        return scc_syscall2((uint64_t)fd, (uint64_t)tptr, 139);
    }
    

    static int scc_adjtime(struct timeval *delta, struct timeval *olddelta) {
        return scc_syscall2((uint64_t)delta, (uint64_t)olddelta, 140);
    }
    

    static int scc_gethostuuid(unsigned char *uuid_buf, const struct timespec *timeoutp, int spi) {
        return scc_syscall3((uint64_t)uuid_buf, (uint64_t)timeoutp, (uint64_t)spi, 142);
    }

    static int scc_setsid(void) {
        return scc_syscall0(147);
    }
    
    static int scc_getpgid(pid_t pid) {
        return scc_syscall1((uint64_t)pid, 151);
    }
    

    static int scc_setprivexec(int flag) {
        return scc_syscall1((uint64_t)flag, 152);
    }
    

    static int scc_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, 153);
    }
    

    static int scc_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, 154);
    }
    

    static int scc_nfssvc(int flag, caddr_t argp) {
        return scc_syscall2((uint64_t)flag, (uint64_t)argp, 155);
    }
    
    static int scc_statfs(char *path, struct statfs *buf) {
        return scc_syscall2((uint64_t)path, (uint64_t)buf, 157);
    }
    

    static int scc_fstatfs(int fd, struct statfs *buf) {
        return scc_syscall2((uint64_t)fd, (uint64_t)buf, 158);
    }
    

    static int scc_unmount(char* path, int flags) {
        return scc_syscall2((uint64_t)path, (uint64_t)flags, 159);
    }
    
    static int scc_getfh(char *fname, fhandle_t *fhp) {
        return scc_syscall2((uint64_t)fname, (uint64_t)fhp, 161);
    }
    
    static int scc_quotactl(const char *path, int cmd, int uid, caddr_t arg) {
        return scc_syscall4((uint64_t)path, (uint64_t)cmd, (uint64_t)uid, (uint64_t)arg, 165);
    }

    static int scc_mount(char *type, char *path, int flags, caddr_t data) {
        return scc_syscall4((uint64_t)type, (uint64_t)path, (uint64_t)flags, (uint64_t)data, 167);
    }    

    static int scc_csops(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize) {
        return scc_syscall4((uint64_t)pid, (uint64_t)ops, (uint64_t)useraddr, (uint64_t)usersize, 169);
    }
    

    static int scc_csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken) {
        return scc_syscall5((uint64_t)pid, (uint64_t)ops, (uint64_t)useraddr, (uint64_t)usersize, (uint64_t)uaudittoken, 170);
    }

    static int scc_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
        return scc_syscall4((uint64_t)idtype, (uint64_t)id, (uint64_t)infop, (uint64_t)options, 173);
    }

    static int scc_kdebug_trace(int code, int arg1, int arg2, int arg3, int arg4, int arg5) {
        return scc_syscall6((uint64_t)code, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4, (uint64_t)arg5, 180);
    }
    

    static int scc_setgid(gid_t gid) {
        return scc_syscall1((uint64_t)gid, 181);
    }
    

    static int scc_setegid(gid_t egid) {
        return scc_syscall1((uint64_t)egid, 182);
    }
    

    static int scc_seteuid(uid_t euid) {
        return scc_syscall1((uint64_t)euid, 183);
    }
    

    static int scc_sigreturn(void* *uctx, int infostyle) {
        return scc_syscall2((uint64_t)uctx, (uint64_t)infostyle, 184);
    }
    

    static int scc_chud(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
        return scc_syscall6((uint64_t)code, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4, (uint64_t)arg5, 185);
    }

    static int scc_fdatasync(int fd) {
        return scc_syscall1((uint64_t)fd, 187);
    }
    

    static int scc_stat(user_addr_t path, user_addr_t ub) {
        return scc_syscall2((uint64_t)path, (uint64_t)ub, 188);
    }
    

    static int scc_fstat(int fd, user_addr_t ub) {
        return scc_syscall2((uint64_t)fd, (uint64_t)ub, 189);
    }
    

    static int scc_lstat(user_addr_t path, user_addr_t ub) {
        return scc_syscall2((uint64_t)path, (uint64_t)ub, 190);
    }
    

    static int scc_pathconf(char *path, int name) {
        return scc_syscall2((uint64_t)path, (uint64_t)name, 191);
    }
    

    static int scc_fpathconf(int fd, int name) {
        return scc_syscall2((uint64_t)fd, (uint64_t)name, 192);
    }

    static int scc_getrlimit(u_int which, struct rlimit *rlp) {
        return scc_syscall2((uint64_t)which, (uint64_t)rlp, 194);
    }
    

    static int scc_setrlimit(u_int which, struct rlimit *rlp) {
        return scc_syscall2((uint64_t)which, (uint64_t)rlp, 195);
    }
    

    static int scc_getdirentries(int fd, char *buf, u_int count, long *basep) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)count, (uint64_t)basep, 196);
    }
    

    static int scc_mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos) {
        return scc_syscall6((uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t)flags, (uint64_t)fd, (uint64_t)pos, 197);
    }

    static int scc_lseek(int fd, off_t offset, int whence) {
        return scc_syscall3((uint64_t)fd, (uint64_t)offset, (uint64_t)whence, 199);
    }
    

    static int scc_truncate(char *path, off_t length) {
        return scc_syscall2((uint64_t)path, (uint64_t)length, 200);
    }
    

    static int scc_ftruncate(int fd, off_t length) {
        return scc_syscall2((uint64_t)fd, (uint64_t)length, 201);
    }
    

    static int scc_sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen) {
        return scc_syscall6((uint64_t)name, (uint64_t)namelen, (uint64_t)old, (uint64_t)oldlenp, (uint64_t)new, (uint64_t)newlen, 202);
    }
    

    static int scc_mlock(caddr_t addr, size_t len) {
        return scc_syscall2((uint64_t)addr, (uint64_t)len, 203);
    }
    

    static int scc_munlock(caddr_t addr, size_t len) {
        return scc_syscall2((uint64_t)addr, (uint64_t)len, 204);
    }
    

    static int scc_undelete(user_addr_t path) {
        return scc_syscall1((uint64_t)path, 205);
    }

    static int scc_open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode) {
        return scc_syscall5((uint64_t)path, (uint64_t)flags, (uint64_t)class, (uint64_t)dpflags, (uint64_t)mode, 216);
    }

    static int scc_getattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
        return scc_syscall5((uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 220);
    }
    

    static int scc_setattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
        return scc_syscall5((uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 221);
    }
    

    static int scc_getdirentriesattr(int fd, struct attrlist *alist, void *buffer, size_t buffersize, u_long *count, u_long *basep, u_long *newstate, u_long options) {
        return scc_syscall8((uint64_t)fd, (uint64_t)alist, (uint64_t)buffer, (uint64_t)buffersize, (uint64_t)count, (uint64_t)basep, (uint64_t)newstate, (uint64_t)options, 222);
    }
    

    static int scc_exchangedata(const char *path1, const char *path2, u_long options) {
        return scc_syscall3((uint64_t)path1, (uint64_t)path2, (uint64_t)options, 223);
    }
    
    static int scc_searchfs(const char *path, struct fssearchblock *searchblock, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct searchstate *state) {
        return scc_syscall6((uint64_t)path, (uint64_t)searchblock, (uint64_t)nummatches, (uint64_t)scriptcode, (uint64_t)options, (uint64_t)state, 225);
    }
    

    static int scc_delete(user_addr_t path) {
        return scc_syscall1((uint64_t)path, 226);
    }
    

    static int scc_copyfile(char *from, char *to, int mode, int flags) {
        return scc_syscall4((uint64_t)from, (uint64_t)to, (uint64_t)mode, (uint64_t)flags, 227);
    }
    

    static int scc_fgetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
        return scc_syscall5((uint64_t)fd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 228);
    }
    

    static int scc_fsetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
        return scc_syscall5((uint64_t)fd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 229);
    }
    

    static int scc_poll(struct pollfd *fds, u_int nfds, int timeout) {
        return scc_syscall3((uint64_t)fds, (uint64_t)nfds, (uint64_t)timeout, 230);
    }
    

    static int scc_watchevent(struct eventreq *u_req, int u_eventmask) {
        return scc_syscall2((uint64_t)u_req, (uint64_t)u_eventmask, 231);
    }
    

    static int scc_waitevent(struct eventreq *u_req, struct timeval *tv) {
        return scc_syscall2((uint64_t)u_req, (uint64_t)tv, 232);
    }
    

    static int scc_modwatch(struct eventreq *u_req, int u_eventmask) {
        return scc_syscall2((uint64_t)u_req, (uint64_t)u_eventmask, 233);
    }
    

    static int scc_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
        return scc_syscall6((uint64_t)path, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, 234);
    }
    

    static int scc_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
        return scc_syscall6((uint64_t)fd, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, 235);
    }
    

    static int scc_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
        return scc_syscall6((uint64_t)path, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, 236);
    }
    

    static int scc_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
        return scc_syscall6((uint64_t)fd, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, 237);
    }
    

    static int scc_removexattr(user_addr_t path, user_addr_t attrname, int options) {
        return scc_syscall3((uint64_t)path, (uint64_t)attrname, (uint64_t)options, 238);
    }
    

    static int scc_fremovexattr(int fd, user_addr_t attrname, int options) {
        return scc_syscall3((uint64_t)fd, (uint64_t)attrname, (uint64_t)options, 239);
    }
    

    static int scc_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize, int options) {
        return scc_syscall4((uint64_t)path, (uint64_t)namebuf, (uint64_t)bufsize, (uint64_t)options, 240);
    }
    

    static int scc_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options) {
        return scc_syscall4((uint64_t)fd, (uint64_t)namebuf, (uint64_t)bufsize, (uint64_t)options, 241);
    }
    

    static int scc_fsctl(const char *path, u_long cmd, caddr_t data, u_int options) {
        return scc_syscall4((uint64_t)path, (uint64_t)cmd, (uint64_t)data, (uint64_t)options, 242);
    }
    

    static int scc_initgroups(u_int gidsetsize, gid_t *gidset, int gmuid) {
        return scc_syscall3((uint64_t)gidsetsize, (uint64_t)gidset, (uint64_t)gmuid, 243);
    }
    

    static int scc_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *adesc, char **argv, char **envp) {
        return scc_syscall5((uint64_t)pid, (uint64_t)path, (uint64_t)adesc, (uint64_t)argv, (uint64_t)envp, 244);
    }
    

    static int scc_ffsctl(int fd, u_long cmd, caddr_t data, u_int options) {
        return scc_syscall4((uint64_t)fd, (uint64_t)cmd, (uint64_t)data, (uint64_t)options, 245);
    }

    static int scc_nfsclnt(int flag, caddr_t argp) {
        return scc_syscall2((uint64_t)flag, (uint64_t)argp, 247);
    }
    

    static int scc_fhopen(const struct fhandle *u_fhp, int flags) {
        return scc_syscall2((uint64_t)u_fhp, (uint64_t)flags, 248);
    }

    static int scc_minherit(void *addr, size_t len, int inherit) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)inherit, 250);
    }
    

    static int scc_semsys(u_int which, int a2, int a3, int a4, int a5) {
        return scc_syscall5((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (uint64_t)a5, 251);
    }
    

    static int scc_msgsys(u_int which, int a2, int a3, int a4, int a5) {
        return scc_syscall5((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (uint64_t)a5, 252);
    }
    

    static int scc_shmsys(u_int which, int a2, int a3, int a4) {
        return scc_syscall4((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, 253);
    }
    

    static int scc_semctl(int semid, int semnum, int cmd, user_semun_t _arg) {
        return scc_syscall4((uint64_t)semid, (uint64_t)semnum, (uint64_t)cmd, (uint64_t)_arg.buf, 254);
    }
    

    static int scc_semget(key_t key, int nsems, int semflg) {
        return scc_syscall3((uint64_t)key, (uint64_t)nsems, (uint64_t)semflg, 255);
    }
    

    static int scc_semop(int semid, struct sembuf *sops, int nsops) {
        return scc_syscall3((uint64_t)semid, (uint64_t)sops, (uint64_t)nsops, 256);
    }
    
    static int scc_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
        return scc_syscall3((uint64_t)msqid, (uint64_t)cmd, (uint64_t)buf, 258);
    }
    

    static int scc_msgget(key_t key, int msgflg) {
        return scc_syscall2((uint64_t)key, (uint64_t)msgflg, 259);
    }
    

    static int scc_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg) {
        return scc_syscall4((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgflg, 260);
    }
    

    static int scc_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
        return scc_syscall5((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgtyp, (uint64_t)msgflg, 261);
    }
    

    static int scc_shmat(int shmid, void *shmaddr, int shmflg) {
        return scc_syscall3((uint64_t)shmid, (uint64_t)shmaddr, (uint64_t)shmflg, 262);
    }
    

    static int scc_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
        return scc_syscall3((uint64_t)shmid, (uint64_t)cmd, (uint64_t)buf, 263);
    }
    

    static int scc_shmdt(void *shmaddr) {
        return scc_syscall1((uint64_t)shmaddr, 264);
    }
    

    static int scc_shmget(key_t key, size_t size, int shmflg) {
        return scc_syscall3((uint64_t)key, (uint64_t)size, (uint64_t)shmflg, 265);
    }
    

    static int scc_shm_open(const char *name, int oflag, int mode) {
        return scc_syscall3((uint64_t)name, (uint64_t)oflag, (uint64_t)mode, 266);
    }
    

    static int scc_shm_unlink(const char *name) {
        return scc_syscall1((uint64_t)name, 267);
    }
    

    static int scc_sem_open(const char *name, int oflag, int mode, int value) {
        return scc_syscall4((uint64_t)name, (uint64_t)oflag, (uint64_t)mode, (uint64_t)value, 268);
    }
    

    static int scc_sem_close(sem_t *sem) {
        return scc_syscall1((uint64_t)sem, 269);
    }
    

    static int scc_sem_unlink(const char *name) {
        return scc_syscall1((uint64_t)name, 270);
    }
    

    static int scc_sem_wait(sem_t *sem) {
        return scc_syscall1((uint64_t)sem, 271);
    }
    

    static int scc_sem_trywait(sem_t *sem) {
        return scc_syscall1((uint64_t)sem, 272);
    }
    

    static int scc_sem_post(sem_t *sem) {
        return scc_syscall1((uint64_t)sem, 273);
    }
    

    static int scc_sysctlbyname(const char *name, size_t namelen, void *old, size_t *oldlenp, void *new, size_t newlen) {
        return scc_syscall6((uint64_t)name, (uint64_t)namelen, (uint64_t)old, (uint64_t)oldlenp, (uint64_t)new, (uint64_t)newlen, 274);
    }
    
    static int scc_open_extended(user_addr_t path, int flags, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
        return scc_syscall6((uint64_t)path, (uint64_t)flags, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, 277);
    }
    

    static int scc_umask_extended(int newmask, user_addr_t xsecurity) {
        return scc_syscall2((uint64_t)newmask, (uint64_t)xsecurity, 278);
    }
    

    static int scc_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 279);
    }
    

    static int scc_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 280);
    }
    

    static int scc_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)fd, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 281);
    }
    

    static int scc_chmod_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
        return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, 282);
    }
    

    static int scc_fchmod_extended(int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
        return scc_syscall5((uint64_t)fd, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, 283);
    }
    

    static int scc_access_extended(user_addr_t entries, size_t size, user_addr_t results, uid_t uid) {
        return scc_syscall4((uint64_t)entries, (uint64_t)size, (uint64_t)results, (uint64_t)uid, 284);
    }
    

    static int scc_settid(uid_t uid, gid_t gid) {
        return scc_syscall2((uint64_t)uid, (uint64_t)gid, 285);
    }
    

    static int scc_gettid(uid_t *uidp, gid_t *gidp) {
        return scc_syscall2((uint64_t)uidp, (uint64_t)gidp, 286);
    }
    

    static int scc_setsgroups(int setlen, user_addr_t guidset) {
        return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, 287);
    }
    

    static int scc_getsgroups(user_addr_t setlen, user_addr_t guidset) {
        return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, 288);
    }
    

    static int scc_setwgroups(int setlen, user_addr_t guidset) {
        return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, 289);
    }
    

    static int scc_getwgroups(user_addr_t setlen, user_addr_t guidset) {
        return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, 290);
    }
    

    static int scc_mkfifo_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
        return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, 291);
    }
    

    static int scc_mkdir_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
        return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, 292);
    }
    

    static int scc_identitysvc(int opcode, user_addr_t message) {
        return scc_syscall2((uint64_t)opcode, (uint64_t)message, 293);
    }
    

    static int scc_shared_region_check_np(uint64_t *start_address) {
        return scc_syscall1((uint64_t)start_address, 294);
    }

    static int scc_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored, uint32_t *pages_reclaimed) {
        return scc_syscall3((uint64_t)wait_for_pressure, (uint64_t)nsecs_monitored, (uint64_t)pages_reclaimed, 296);
    }
    

    static int scc_psynch_rw_longrdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 297);
    }
    

    static int scc_psynch_rw_yieldwrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 298);
    }

    static int scc_psynch_mutexwait(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) {
        return scc_syscall5((uint64_t)mutex, (uint64_t)mgen, (uint64_t)ugen, (uint64_t)tid, (uint64_t)flags, 301);
    }
    

    static int scc_psynch_mutexdrop(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) {
        return scc_syscall5((uint64_t)mutex, (uint64_t)mgen, (uint64_t)ugen, (uint64_t)tid, (uint64_t)flags, 302);
    }
    

    static int scc_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex,  uint64_t mugen, uint64_t tid) {
        return scc_syscall7((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvudgen, (uint64_t)flags, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)tid, 303);
    }
    

    static int scc_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex,  uint64_t mugen, uint64_t tid, uint32_t flags) {
        return scc_syscall8((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvugen, (uint64_t)thread_port, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)tid, (uint64_t)flags, 304);
    }
    

    static int scc_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec) {
        return scc_syscall8((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvugen, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)flags, (uint64_t)sec, (uint64_t)nsec, 305);
    }
    

    static int scc_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 306);
    }
    

    static int scc_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 307);
    }
    

    static int scc_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 308);
    }
    

    static int scc_psynch_rw_unlock2(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
        return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, 309);
    }
    

    static int scc_getsid(pid_t pid) {
        return scc_syscall1((uint64_t)pid, 310);
    }
    

    static int scc_settid_with_pid(pid_t pid, int assume) {
        return scc_syscall2((uint64_t)pid, (uint64_t)assume, 311);
    }
    

    static int scc_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags) {
        return scc_syscall7((uint64_t)cv, (uint64_t)cvgen, (uint64_t)cvugen, (uint64_t)cvsgen, (uint64_t)prepocnt, (uint64_t)preposeq, (uint64_t)flags, 312);
    }
    

    static int scc_aio_fsync(int op, user_addr_t aiocbp) {
        return scc_syscall2((uint64_t)op, (uint64_t)aiocbp, 313);
    }
    

    static int scc_aio_return(user_addr_t aiocbp) {
        return scc_syscall1((uint64_t)aiocbp, 314);
    }
    

    static int scc_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp) {
        return scc_syscall3((uint64_t)aiocblist, (uint64_t)nent, (uint64_t)timeoutp, 315);
    }
    

    static int scc_aio_cancel(int fd, user_addr_t aiocbp) {
        return scc_syscall2((uint64_t)fd, (uint64_t)aiocbp, 316);
    }
    

    static int scc_aio_error(user_addr_t aiocbp) {
        return scc_syscall1((uint64_t)aiocbp, 317);
    }
    

    static int scc_aio_read(user_addr_t aiocbp) {
        return scc_syscall1((uint64_t)aiocbp, 318);
    }
    

    static int scc_aio_write(user_addr_t aiocbp) {
        return scc_syscall1((uint64_t)aiocbp, 319);
    }
    

    static int scc_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp) {
        return scc_syscall4((uint64_t)mode, (uint64_t)aiocblist, (uint64_t)nent, (uint64_t)sigp, 320);
    }

    static int scc_iopolicysys(int cmd, void *arg) {
        return scc_syscall2((uint64_t)cmd, (uint64_t)arg, 322);
    }
    

    static int scc_process_policy(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, pid_t target_pid, uint64_t target_threadid) {
        return scc_syscall7((uint64_t)scope, (uint64_t)action, (uint64_t)policy, (uint64_t)policy_subtype, (uint64_t)attrp, (uint64_t)target_pid, (uint64_t)target_threadid, 323);
    }
    

    static int scc_mlockall(int how) {
        return scc_syscall1((uint64_t)how, 324);
    }
    

    static int scc_munlockall(int how) {
        return scc_syscall1((uint64_t)how, 325);
    }

    static int scc_issetugid(void) {
        return scc_syscall0(327);
    }
    

    static int scc___pthread_kill(int thread_port, int sig) {
        return scc_syscall2((uint64_t)thread_port, (uint64_t)sig, 328);
    }
    

    static int scc___pthread_sigmask(int how, user_addr_t set, user_addr_t oset) {
        return scc_syscall3((uint64_t)how, (uint64_t)set, (uint64_t)oset, 329);
    }
    

    static int scc___sigwait(user_addr_t set, user_addr_t sig) {
        return scc_syscall2((uint64_t)set, (uint64_t)sig, 330);
    }
    

    static int scc___disable_threadsignal(int value) {
        return scc_syscall1((uint64_t)value, 331);
    }
    

    static int scc___pthread_markcancel(int thread_port) {
        return scc_syscall1((uint64_t)thread_port, 332);
    }
    

    static int scc___pthread_canceled(int  action) {
        return scc_syscall1((uint64_t)action, 333);
    }
    

    static int scc___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) {
        return scc_syscall6((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)tv_sec, (uint64_t)tv_nsec, 334);
    }
    
    static int scc_proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) {
        return scc_syscall6((uint64_t)callnum, (uint64_t)pid, (uint64_t)flavor, (uint64_t)arg, (uint64_t)buffer, (uint64_t)buffersize, 336);
    }
    

    static int scc_sendfile(int fd, int s, off_t offset, off_t *nbytes, struct sf_hdtr *hdtr, int flags) {
        return scc_syscall6((uint64_t)fd, (uint64_t)s, (uint64_t)offset, (uint64_t)nbytes, (uint64_t)hdtr, (uint64_t)flags, 337);
    }
    

    static int scc_stat64(user_addr_t path, user_addr_t ub) {
        return scc_syscall2((uint64_t)path, (uint64_t)ub, 338);
    }
    

    static int scc_fstat64(int fd, user_addr_t ub) {
        return scc_syscall2((uint64_t)fd, (uint64_t)ub, 339);
    }
    

    static int scc_lstat64(user_addr_t path, user_addr_t ub) {
        return scc_syscall2((uint64_t)path, (uint64_t)ub, 340);
    }
    

    static int scc_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 341);
    }
    

    static int scc_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 342);
    }
    

    static int scc_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
        return scc_syscall4((uint64_t)fd, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, 343);
    }
    

    static int scc_getdirentries64(int fd, void *buf, user_size_t bufsize, off_t *position) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)bufsize, (uint64_t)position, 344);
    }
    

    static int scc_statfs64(char *path, void *buf) {
        return scc_syscall2((uint64_t)path, (uint64_t)buf, 345);
    }
    

    static int scc_fstatfs64(int fd, void *buf) {
        return scc_syscall2((uint64_t)fd, (uint64_t)buf, 346);
    }
    

    static int scc_getfsstat64(user_addr_t buf, int bufsize, int flags) {
        return scc_syscall3((uint64_t)buf, (uint64_t)bufsize, (uint64_t)flags, 347);
    }
    

    static int scc___pthread_chdir(user_addr_t path) {
        return scc_syscall1((uint64_t)path, 348);
    }
    

    static int scc___pthread_fchdir(int fd) {
        return scc_syscall1((uint64_t)fd, 349);
    }
    

    static int scc_audit(void *record, int length) {
        return scc_syscall2((uint64_t)record, (uint64_t)length, 350);
    }
    

    static int scc_auditon(int cmd, void *data, int length) {
        return scc_syscall3((uint64_t)cmd, (uint64_t)data, (uint64_t)length, 351);
    }

    static int scc_getauid(au_id_t *auid) {
        return scc_syscall1((uint64_t)auid, 353);
    }
    

    static int scc_setauid(au_id_t *auid) {
        return scc_syscall1((uint64_t)auid, 354);
    }

    static int scc_getaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) {
        return scc_syscall2((uint64_t)auditinfo_addr, (uint64_t)length, 357);
    }
    

    static int scc_setaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) {
        return scc_syscall2((uint64_t)auditinfo_addr, (uint64_t)length, 358);
    }
    

    static int scc_auditctl(char *path) {
        return scc_syscall1((uint64_t)path, 359);
    }
    

    static int scc_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack, user_addr_t pthread, uint32_t flags) {
        return scc_syscall5((uint64_t)func, (uint64_t)func_arg, (uint64_t)stack, (uint64_t)pthread, (uint64_t)flags, 360);
    }
    

    static int scc_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port, uint32_t sem) {
        return scc_syscall4((uint64_t)stackaddr, (uint64_t)freesize, (uint64_t)port, (uint64_t)sem, 361);
    }
    

    static int scc_kqueue(void) {
        return scc_syscall0(362);
    }
    

    static int scc_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout) {
        return scc_syscall6((uint64_t)fd, (uint64_t)changelist, (uint64_t)nchanges, (uint64_t)eventlist, (uint64_t)nevents, (uint64_t)timeout, 363);
    }
    

    static int scc_lchown(user_addr_t path, uid_t owner, gid_t group) {
        return scc_syscall3((uint64_t)path, (uint64_t)owner, (uint64_t)group, 364);
    }
    

    static int scc_stack_snapshot(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset) {
        return scc_syscall5((uint64_t)pid, (uint64_t)tracebuf, (uint64_t)tracebuf_size, (uint64_t)flags, (uint64_t)dispatch_offset, 365);
    }
    

    static int scc_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset) {
        return scc_syscall7((uint64_t)threadstart, (uint64_t)wqthread, (uint64_t)flags, (uint64_t)stack_addr_hint, (uint64_t)targetconc_ptr, (uint64_t)dispatchqueue_offset, (uint64_t)tsd_offset, 366);
    }
    

    static int scc_workq_open(void) {
        return scc_syscall0(367);
    }
    

    static int scc_workq_kernreturn(int options, user_addr_t item, int affinity, int prio) {
        return scc_syscall4((uint64_t)options, (uint64_t)item, (uint64_t)affinity, (uint64_t)prio, 368);
    }
    

    static int scc_kevent64(int fd, const struct kevent64_s *changelist, int nchanges, struct kevent64_s *eventlist, int nevents, unsigned int flags, const struct timespec *timeout) {
        return scc_syscall7((uint64_t)fd, (uint64_t)changelist, (uint64_t)nchanges, (uint64_t)eventlist, (uint64_t)nevents, (uint64_t)flags, (uint64_t)timeout, 369);
    }
    

    static int scc___old_semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) {
        return scc_syscall5((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)ts, 370);
    }
    

    static int scc___old_semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) {
        return scc_syscall5((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)ts, 371);
    }
    

    static int scc_thread_selfid(void) {
        return scc_syscall0(372);
    }
    

    static int scc_ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3) {
        return scc_syscall4((uint64_t)cmd, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 373);
    }

    static int scc___mac_execve(char *fname, char **argp, char **envp, mac_t mac_p) {
        return scc_syscall4((uint64_t)fname, (uint64_t)argp, (uint64_t)envp, (uint64_t)mac_p, 380);
    }
    
    static int scc___mac_get_file(char *path_p, mac_t mac_p) {
        return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, 382);
    }
    

    static int scc___mac_set_file(char *path_p, mac_t mac_p) {
        return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, 383);
    }
    

    static int scc___mac_get_link(char *path_p, mac_t mac_p) {
        return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, 384);
    }
    

    static int scc___mac_set_link(char *path_p, mac_t mac_p) {
        return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, 385);
    }
    

    static int scc___mac_get_proc(mac_t mac_p) {
        return scc_syscall1((uint64_t)mac_p, 386);
    }
    

    static int scc___mac_set_proc(mac_t mac_p) {
        return scc_syscall1((uint64_t)mac_p, 387);
    }
    

    static int scc___mac_get_fd(int fd, mac_t mac_p) {
        return scc_syscall2((uint64_t)fd, (uint64_t)mac_p, 388);
    }
    

    static int scc___mac_set_fd(int fd, mac_t mac_p) {
        return scc_syscall2((uint64_t)fd, (uint64_t)mac_p, 389);
    }
    

    static int scc___mac_get_pid(pid_t pid, mac_t mac_p) {
        return scc_syscall2((uint64_t)pid, (uint64_t)mac_p, 390);
    }
    

    static int scc___mac_get_lcid(pid_t lcid, mac_t mac_p) {
        return scc_syscall2((uint64_t)lcid, (uint64_t)mac_p, 391);
    }
    

    static int scc___mac_get_lctx(mac_t mac_p) {
        return scc_syscall1((uint64_t)mac_p, 392);
    }
    

    static int scc___mac_set_lctx(mac_t mac_p) {
        return scc_syscall1((uint64_t)mac_p, 393);
    }
    

    static int scc_setlcid(pid_t pid, pid_t lcid) {
        return scc_syscall2((uint64_t)pid, (uint64_t)lcid, 394);
    }
    

    static int scc_getlcid(pid_t pid) {
        return scc_syscall1((uint64_t)pid, 395);
    }
    

    static int scc_read_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, 396);
    }
    

    static int scc_write_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, 397);
    }
    

    static int scc_open_nocancel(user_addr_t path, int flags, int mode) {
        return scc_syscall3((uint64_t)path, (uint64_t)flags, (uint64_t)mode, 398);
    }
    

    static int scc_close_nocancel(int fd) {
        return scc_syscall1((uint64_t)fd, 399);
    }
    

    static int scc_wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) {
        return scc_syscall4((uint64_t)pid, (uint64_t)status, (uint64_t)options, (uint64_t)rusage, 400);
    }
    

    static int scc_recvmsg_nocancel(int s, struct msghdr *msg, int flags) {
        return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, 401);
    }
    

    static int scc_sendmsg_nocancel(int s, caddr_t msg, int flags) {
        return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, 402);
    }
    

    static int scc_recvfrom_nocancel(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) {
        return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)from, (uint64_t)fromlenaddr, 403);
    }
    

    static int scc_accept_nocancel(int s, caddr_t name, socklen_t *anamelen) {
        return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)anamelen, 404);
    }
    

    static int scc_msync_nocancel(caddr_t addr, size_t len, int flags) {
        return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)flags, 405);
    }
    

    static int scc_fcntl_nocancel(int fd, int cmd, long arg) {
        return scc_syscall3((uint64_t)fd, (uint64_t)cmd, (uint64_t)arg, 406);
    }
    

    static int scc_select_nocancel(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) {
        return scc_syscall5((uint64_t)nd, (uint64_t)in, (uint64_t)ou, (uint64_t)ex, (uint64_t)tv, 407);
    }
    

    static int scc_fsync_nocancel(int fd) {
        return scc_syscall1((uint64_t)fd, 408);
    }
    

    static int scc_connect_nocancel(int s, caddr_t name, socklen_t namelen) {
        return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, 409);
    }
    

    static int scc_sigsuspend_nocancel(sigset_t mask) {
        return scc_syscall1((uint64_t)mask, 410);
    }
    

    static int scc_readv_nocancel(int fd, struct iovec *iovp, u_int iovcnt) {
        return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, 411);
    }
    

    static int scc_writev_nocancel(int fd, struct iovec *iovp, u_int iovcnt) {
        return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, 412);
    }
    

    static int scc_sendto_nocancel(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) {
        return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)to, (uint64_t)tolen, 413);
    }
    

    static int scc_pread_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, 414);
    }
    

    static int scc_pwrite_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
        return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, 415);
    }
    

    static int scc_waitid_nocancel(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
        return scc_syscall4((uint64_t)idtype, (uint64_t)id, (uint64_t)infop, (uint64_t)options, 416);
    }
    

    static int scc_poll_nocancel(struct pollfd *fds, u_int nfds, int timeout) {
        return scc_syscall3((uint64_t)fds, (uint64_t)nfds, (uint64_t)timeout, 417);
    }
    

    static int scc_msgsnd_nocancel(int msqid, void *msgp, size_t msgsz, int msgflg) {
        return scc_syscall4((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgflg, 418);
    }
    

    static int scc_msgrcv_nocancel(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
        return scc_syscall5((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgtyp, (uint64_t)msgflg, 419);
    }
    

    static int scc_sem_wait_nocancel(sem_t *sem) {
        return scc_syscall1((uint64_t)sem, 420);
    }
    

    static int scc_aio_suspend_nocancel(user_addr_t aiocblist, int nent, user_addr_t timeoutp) {
        return scc_syscall3((uint64_t)aiocblist, (uint64_t)nent, (uint64_t)timeoutp, 421);
    }
    

    static int scc___sigwait_nocancel(user_addr_t set, user_addr_t sig) {
        return scc_syscall2((uint64_t)set, (uint64_t)sig, 422);
    }
    

    static int scc___semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) {
        return scc_syscall6((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)tv_sec, (uint64_t)tv_nsec, 423);
    }
    

    static int scc___mac_mount(char *type, char *path, int flags, caddr_t data, mac_t mac_p) {
        return scc_syscall5((uint64_t)type, (uint64_t)path, (uint64_t)flags, (uint64_t)data, (uint64_t)mac_p, 424);
    }
    

    static int scc___mac_get_mount(char *path, mac_t mac_p) {
        return scc_syscall2((uint64_t)path, (uint64_t)mac_p, 425);
    }
    

    static int scc___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize, int flags) {
        return scc_syscall5((uint64_t)buf, (uint64_t)bufsize, (uint64_t)mac, (uint64_t)macsize, (uint64_t)flags, 426);
    }
    

    static int scc_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid) {
        return scc_syscall4((uint64_t)buf, (uint64_t)bufsize, (uint64_t)fsid, (uint64_t)objid, 427);
    }
    

    static int scc_audit_session_self(void) {
        return scc_syscall0(428);
    }
    

    static int scc_audit_session_join(mach_port_name_t port) {
        return scc_syscall1((uint64_t)port, 429);
    }
    

    static int scc_fileport_makeport(int fd, user_addr_t portnamep) {
        return scc_syscall2((uint64_t)fd, (uint64_t)portnamep, 430);
    }
    

    static int scc_fileport_makefd(mach_port_name_t port) {
        return scc_syscall1((uint64_t)port, 431);
    }
    

    static int scc_audit_session_port(au_asid_t asid, user_addr_t portnamep) {
        return scc_syscall2((uint64_t)asid, (uint64_t)portnamep, 432);
    }
    

    static int scc_pid_suspend(int pid) {
        return scc_syscall1((uint64_t)pid, 433);
    }
    

    static int scc_pid_resume(int pid) {
        return scc_syscall1((uint64_t)pid, 434);
    }

    static int scc_shared_region_map_and_slide_np(int fd, uint32_t count, const struct shared_file_mapping_np *mappings, uint32_t slide, uint64_t* slide_start, uint32_t slide_size) {
        return scc_syscall6((uint64_t)fd, (uint64_t)count, (uint64_t)mappings, (uint64_t)slide, (uint64_t)slide_start, (uint64_t)slide_size, 438);
    }
    

    static int scc_kas_info(int selector, void *value, size_t *size) {
        return scc_syscall3((uint64_t)selector, (uint64_t)value, (uint64_t)size, 439);
    }
    

    static int scc_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize) {
        return scc_syscall5((uint64_t)command, (uint64_t)pid, (uint64_t)flags, (uint64_t)buffer, (uint64_t)buffersize, 440);
    }
    

    static int scc_guarded_open_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int mode) {
        return scc_syscall5((uint64_t)path, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)flags, (uint64_t)mode, 441);
    }
    

    static int scc_guarded_close_np(int fd, const guardid_t *guard) {
        return scc_syscall2((uint64_t)fd, (uint64_t)guard, 442);
    }
    

    static int scc_guarded_kqueue_np(const guardid_t *guard, u_int guardflags) {
        return scc_syscall2((uint64_t)guard, (uint64_t)guardflags, 443);
    }
    

    static int scc_change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags, const guardid_t *nguard, u_int nguardflags, int *fdflagsp) {
        return scc_syscall6((uint64_t)fd, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)nguard, (uint64_t)nguardflags, (uint64_t)fdflagsp, 444);
    }

    static int scc_proc_rlimit_control(pid_t pid, int flavor, void *arg) {
        return scc_syscall3((uint64_t)pid, (uint64_t)flavor, (uint64_t)arg, 446);
    }
    

    static int scc_connectx(int s, struct sockaddr *src, socklen_t srclen, struct sockaddr *dsts, socklen_t dstlen, uint32_t ifscope, associd_t aid, connid_t *cid) {
        return scc_syscall8((uint64_t)s, (uint64_t)src, (uint64_t)srclen, (uint64_t)dsts, (uint64_t)dstlen, (uint64_t)ifscope, (uint64_t)aid, (uint64_t)cid, 447);
    }
    

    static int scc_disconnectx(int s, associd_t aid, connid_t cid) {
        return scc_syscall3((uint64_t)s, (uint64_t)aid, (uint64_t)cid, 448);
    }
    

    static int scc_peeloff(int s, associd_t aid) {
        return scc_syscall2((uint64_t)s, (uint64_t)aid, 449);
    }
    

    static int scc_socket_delegate(int domain, int type, int protocol, pid_t epid) {
        return scc_syscall4((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, (uint64_t)epid, 450);
    }
    

    static int scc_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval, uint64_t leeway, uint64_t arg4, uint64_t arg5) {
        return scc_syscall6((uint64_t)cmd, (uint64_t)deadline, (uint64_t)interval, (uint64_t)leeway, (uint64_t)arg4, (uint64_t)arg5, 451);
    }
    

    static int scc_proc_uuid_policy(uint32_t operation, uuid_t uuid, size_t uuidlen, uint32_t flags) {
        return scc_syscall4((uint64_t)operation, (uint64_t)uuid, (uint64_t)uuidlen, (uint64_t)flags, 452);
    }
    

    static int scc_memorystatus_get_level(user_addr_t level) {
        return scc_syscall1((uint64_t)level, 453);
    }
    

    static int scc_system_override(uint64_t timeout, uint64_t flags) {
        return scc_syscall2((uint64_t)timeout, (uint64_t)flags, 454);
    }
    

    static int scc_vfs_purge(void) {
        return scc_syscall0(455);
    }
    

    static int scc_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time, uint64_t *out_time) {
        return scc_syscall4((uint64_t)operation, (uint64_t)sfi_class, (uint64_t)time, (uint64_t)out_time, 456);
    }
    

    static int scc_sfi_pidctl(uint32_t operation, pid_t pid, uint32_t sfi_flags, uint32_t *out_sfi_flags) {
        return scc_syscall4((uint64_t)operation, (uint64_t)pid, (uint64_t)sfi_flags, (uint64_t)out_sfi_flags, 457);
    }

    static int scc_necp_match_policy(uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result) {
        return scc_syscall3((uint64_t)parameters, (uint64_t)parameters_size, (uint64_t)returned_result, 460);
    }
    

    static int scc_getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, uint64_t options) {
        return scc_syscall5((uint64_t)dirfd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 461);
    }

    static int scc_openat(int fd, user_addr_t path, int flags, int mode) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)flags, (uint64_t)mode, 463);
    }
    

    static int scc_openat_nocancel(int fd, user_addr_t path, int flags, int mode) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)flags, (uint64_t)mode, 464);
    }
    

    static int scc_renameat(int fromfd, char *from, int tofd, char *to) {
        return scc_syscall4((uint64_t)fromfd, (uint64_t)from, (uint64_t)tofd, (uint64_t)to, 465);
    }
    

    static int scc_faccessat(int fd, user_addr_t path, int amode, int flag) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)amode, (uint64_t)flag, 466);
    }
    

    static int scc_fchmodat(int fd, user_addr_t path, int mode, int flag) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)mode, (uint64_t)flag, 467);
    }
    

    static int scc_fchownat(int fd, user_addr_t path, uid_t uid,gid_t gid, int flag) {
        return scc_syscall5((uint64_t)fd, (uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)flag, 468);
    }
    

    static int scc_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)ub, (uint64_t)flag, 469);
    }
    

    static int scc_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)ub, (uint64_t)flag, 470);
    }
    

    static int scc_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag) {
        return scc_syscall5((uint64_t)fd1, (uint64_t)path, (uint64_t)fd2, (uint64_t)link, (uint64_t)flag, 471);
    }
    

    static int scc_unlinkat(int fd, user_addr_t path, int flag) {
        return scc_syscall3((uint64_t)fd, (uint64_t)path, (uint64_t)flag, 472);
    }
    

    static int scc_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize) {
        return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)buf, (uint64_t)bufsize, 473);
    }
    

    static int scc_symlinkat(user_addr_t *path1, int fd, user_addr_t path2) {
        return scc_syscall3((uint64_t)path1, (uint64_t)fd, (uint64_t)path2, 474);
    }
    

    static int scc_mkdirat(int fd, user_addr_t path, int mode) {
        return scc_syscall3((uint64_t)fd, (uint64_t)path, (uint64_t)mode, 475);
    }
    

    static int scc_getattrlistat(int fd, const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
        return scc_syscall6((uint64_t)fd, (uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, 476);
    }
    

    static int scc_proc_trace_log(pid_t pid, uint64_t uniqueid) {
        return scc_syscall2((uint64_t)pid, (uint64_t)uniqueid, 477);
    }
    

    static int scc_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) {
        return scc_syscall4((uint64_t)cmd, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, 478);
    }
    

    static int scc_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags) {
        return scc_syscall3((uint64_t)fsid, (uint64_t)objid, (uint64_t)oflags, 479);
    }
    

    static int scc_recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) {
        return scc_syscall4((uint64_t)s, (uint64_t)msgp, (uint64_t)cnt, (uint64_t)flags, 480);
    }
    

    static int scc_sendmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) {
        return scc_syscall4((uint64_t)s, (uint64_t)msgp, (uint64_t)cnt, (uint64_t)flags, 481);
    }
    

    static int scc_thread_selfusage(void) {
        return scc_syscall0(482);
    }
    
    static int scc_guarded_open_dprotected_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int dpclass, int dpflags, int mode) {
        return scc_syscall7((uint64_t)path, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)flags, (uint64_t)dpclass, (uint64_t)dpflags, (uint64_t)mode, 484);
    }
    

    static int scc_guarded_write_np(int fd, const guardid_t *guard, user_addr_t cbuf, user_size_t nbyte) {
        return scc_syscall4((uint64_t)fd, (uint64_t)guard, (uint64_t)cbuf, (uint64_t)nbyte, 485);
    }
    

    static int scc_guarded_pwrite_np(int fd, const guardid_t *guard, user_addr_t buf, user_size_t nbyte, off_t offset) {
        return scc_syscall5((uint64_t)fd, (uint64_t)guard, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, 486);
    }
    

    static int scc_guarded_writev_np(int fd, const guardid_t *guard, struct iovec *iovp, u_int iovcnt) {
        return scc_syscall4((uint64_t)fd, (uint64_t)guard, (uint64_t)iovp, (uint64_t)iovcnt, 487);
    }
