#ifdef __x86_64
    #define POSIX_CALL_NUM(num) ( (0x02 << 24) | (num) )
#elif __arm64
    #define POSIX_CALL_NUM(num) (num)
#else
    #error "Unsupported architecture"
#endif



#include <sys/appleapiopts.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/attr.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/sem.h>
#include <sys/resource.h>
#include <spawn.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/mman.h>

typedef int     vm_prot_t;
typedef __uint32_t connid_t;
typedef __uint32_t associd_t;
typedef uint64_t guardid_t;

struct msghdr_x {
    void        *msg_name;  /* optional address */
    socklen_t   msg_namelen;    /* size of address */
    struct iovec    *msg_iov;   /* scatter/gather array */
    int     msg_iovlen; /* # elements in msg_iov */
    void        *msg_control;   /* ancillary data, see below */
    socklen_t   msg_controllen; /* ancillary data buffer len */
    int     msg_flags;  /* flags on received message */
    size_t      msg_datalen;    /* byte length of buffer in msg_iov */
};

struct eventreq {
  int      er_type;
#define EV_FD 1    // file descriptor
  int      er_handle;
  void    *er_data;
  int      er_rcnt;
  int      er_wcnt;
  int      er_ecnt;
  int      er_eventbits;
#define EV_RE  1
#define EV_WR  2
#define EV_EX  4
#define EV_RM  8
#define EV_MASK 0xf
};

struct mac {
    size_t m_buflen;
    char *m_string;
};

typedef struct mac *mac_t;

typedef union {
    u_int                       tunnel_interface_index;
    u_int                       scoped_interface_index;
    u_int32_t                   flow_divert_control_unit;
    u_int32_t                   filter_control_unit;
} necp_kernel_policy_routing_result_parameter;

typedef u_int32_t necp_kernel_policy_result;
typedef u_int32_t necp_kernel_policy_filter;

struct necp_aggregate_result {
    necp_kernel_policy_result           routing_result;
    necp_kernel_policy_routing_result_parameter routing_result_parameter;
    necp_kernel_policy_filter           filter_control_unit;
    necp_kernel_policy_result           service_action;
    uuid_t                              service_uuid;
    u_int32_t                           service_flags;
    u_int32_t                           service_data;
};

struct shared_file_mapping_np {
    mach_vm_address_t   sfm_address;
    mach_vm_size_t      sfm_size;
    mach_vm_offset_t    sfm_file_offset;
    vm_prot_t       sfm_max_prot;
    vm_prot_t       sfm_init_prot;
};

union user_semun {
    user_addr_t buf;        /* buffer for IPC_STAT & IPC_SET */
    user_addr_t array;      /* array for GETALL & SETALL */
};

typedef union user_semun user_semun_t;

typedef uint64_t return_t;

    __attribute__((noreturn)) static void scc_exit(int rval) ;
    static return_t scc_fork(void) ;
    static return_t scc_read(int fd, char* cbuf, user_size_t nbyte) ;
    static return_t scc_write(int fd, char* cbuf, user_size_t nbyte) ;
    static return_t scc_open(char* path, int flags, int mode) ;
    static return_t scc_close(int fd) ;
    static return_t scc_wait4(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static return_t scc_link(char* path, user_addr_t link) ;
    static return_t scc_unlink(char* path) ;
    static return_t scc_chdir(char* path) ;
    static return_t scc_fchdir(int fd) ;
    static return_t scc_mknod(char* path, int mode, int dev) ;
    static return_t scc_chmod(char* path, int mode) ;
    static return_t scc_chown(char* path, int uid, int gid) ;
    static return_t scc_getfsstat(char* buf, int bufsize, int flags) ;
    static return_t scc_getpid(void) ;
    static return_t scc_setuid(uid_t uid) ;
    static return_t scc_getuid(void) ;
    static return_t scc_geteuid(void) ;
    static return_t scc_ptrace(int req, pid_t pid, caddr_t addr, int data) ;
    static return_t scc_recvmsg(int s, struct msghdr *msg, int flags) ;
    static return_t scc_sendmsg(int s, caddr_t msg, int flags) ;
    static return_t scc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static return_t scc_accept(int s, caddr_t name, socklen_t	*anamelen) ;
    static return_t scc_getpeername(int fdes, caddr_t asa, socklen_t *alen) ;
    static return_t scc_getsockname(int fdes, caddr_t asa, socklen_t *alen) ;
    static return_t scc_access(char* path, int flags) ;
    static return_t scc_chflags(char *path, int flags) ;
    static return_t scc_fchflags(int fd, int flags) ;
    static return_t scc_sync(void) ;
    static return_t scc_kill(int pid, int signum, int posix) ;
    static return_t scc_getppid(void) ;
    static return_t scc_dup(u_int fd) ;
    static return_t scc_pipe(void) ;
    static return_t scc_getegid(void) ;
    static return_t scc_sigaction(int signum, struct __sigaction *nsa, struct sigaction *osa) ;
    static return_t scc_getgid(void) ;
    static return_t scc_sigprocmask(int how, user_addr_t mask, user_addr_t omask) ;
    static return_t scc_getlogin(char *namebuf, u_int namelen) ;
    static return_t scc_setlogin(char *namebuf) ;
    static return_t scc_acct(char *path) ;
    static return_t scc_sigpending(struct sigvec *osv) ;
    static return_t scc_sigaltstack(const stack_t *restrict ss, stack_t *restrict oss) ;
    static return_t scc_ioctl(int fd, u_long com, caddr_t data) ;
    static return_t scc_reboot(int opt, char *command) ;
    static return_t scc_revoke(char *path) ;
    static return_t scc_symlink(char *path, char *link) ;
    static return_t scc_readlink(char *path, char *buf, int count) ;
    static return_t scc_execve(char *fname, char **argp, char **envp) ;
    static return_t scc_umask(int newmask) ;
    static return_t scc_chroot(char* path) ;
    static return_t scc_msync(caddr_t addr, size_t len, int flags) ;
    static return_t scc_vfork(void) ;
    static return_t scc_munmap(caddr_t addr, size_t len) ;
    static return_t scc_mprotect(caddr_t addr, size_t len, int prot) ;
    static return_t scc_madvise(caddr_t addr, size_t len, int behav) ;
    static return_t scc_mincore(user_addr_t addr, user_size_t len, user_addr_t vec) ;
    static return_t scc_getgroups(u_int gidsetsize, gid_t *gidset) ;
    static return_t scc_setgroups(u_int gidsetsize, gid_t *gidset) ;
    static return_t scc_getpgrp(void) ;
    static return_t scc_setpgid(int pid, int pgid) ;
    static return_t scc_setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv) ;
    static return_t scc_swapon(void) ;
    static return_t scc_getitimer(u_int which, struct itimerval *itv) ;
    static return_t scc_getdtablesize(void) ;
    static return_t scc_dup2(u_int from, u_int to) ;
    static return_t scc_fcntl(int fd, int cmd, long arg) ;
    static return_t scc_select(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static return_t scc_fsync(int fd) ;
    static return_t scc_setpriority(int which, id_t who, int prio) ;
    static return_t scc_socket(int domain, int type, int protocol) ;
    static return_t scc_connect(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_getpriority(int which, id_t who) ;
    static return_t scc_bind(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_setsockopt(int s, int level, int name, caddr_t val, socklen_t valsize) ;
    static return_t scc_listen(int s, int backlog) ;
    static return_t scc_sigsuspend(sigset_t mask) ;
    static return_t scc_gettimeofday(struct timeval *tp, struct timezone *tzp) ;
    static return_t scc_getrusage(int who, struct rusage *rusage) ;
    static return_t scc_getsockopt(int s, int level, int name, caddr_t val, socklen_t *avalsize) ;
    static return_t scc_readv(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_writev(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_settimeofday(struct timeval *tv, struct timezone *tzp) ;
    static return_t scc_fchown(int fd, int uid, int gid) ;
    static return_t scc_fchmod(int fd, int mode) ;
    static return_t scc_setreuid(uid_t ruid, uid_t euid) ;
    static return_t scc_setregid(gid_t rgid, gid_t egid) ;
    static return_t scc_rename(char *from, char *to) ;
    static return_t scc_flock(int fd, int how) ;
    static return_t scc_mkfifo(char* path, int mode) ;
    static return_t scc_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static return_t scc_shutdown(int s, int how) ;
    static return_t scc_socketpair(int domain, int type, int protocol, int *rsv) ;
    static return_t scc_mkdir(char* path, int mode) ;
    static return_t scc_rmdir(char *path) ;
    static return_t scc_utimes(char *path, struct timeval *tptr) ;
    static return_t scc_futimes(int fd, struct timeval *tptr) ;
    static return_t scc_adjtime(struct timeval *delta, struct timeval *olddelta) ;
    static return_t scc_gethostuuid(unsigned char *uuid_buf, const struct timespec *timeoutp, int spi) ;
    static return_t scc_setsid(void) ;
    static return_t scc_getpgid(pid_t pid) ;
    static return_t scc_setprivexec(int flag) ;
    static return_t scc_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_nfssvc(int flag, caddr_t argp) ;
    static return_t scc_statfs(char *path, struct statfs *buf) ;
    static return_t scc_fstatfs(int fd, struct statfs *buf) ;
    static return_t scc_unmount(char* path, int flags) ;
    static return_t scc_getfh(char *fname, fhandle_t *fhp) ;
    static return_t scc_quotactl(const char *path, int cmd, int uid, caddr_t arg) ;
    static return_t scc_mount(char *type, char *path, int flags, caddr_t data) ;
    static return_t scc_csops(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize) ;
    static return_t scc_csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken) ;
    static return_t scc_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static return_t scc_kdebug_trace(int code, int arg1, int arg2, int arg3, int arg4, int arg5) ;
    static return_t scc_setgid(gid_t gid) ;
    static return_t scc_setegid(gid_t egid) ;
    static return_t scc_seteuid(uid_t euid) ;
    static return_t scc_sigreturn(void* *uctx, int infostyle) ;
    static return_t scc_chud(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) ;
    static return_t scc_fdatasync(int fd) ;
    static return_t scc_stat(user_addr_t path, user_addr_t ub) ;
    static return_t scc_fstat(int fd, user_addr_t ub) ;
    static return_t scc_lstat(user_addr_t path, user_addr_t ub) ;
    static return_t scc_pathconf(char *path, int name) ;
    static return_t scc_fpathconf(int fd, int name) ;
    static return_t scc_getrlimit(u_int which, struct rlimit *rlp) ;
    static return_t scc_setrlimit(u_int which, struct rlimit *rlp) ;
    static return_t scc_getdirentries(int fd, char *buf, u_int count, long *basep) ;
    static return_t scc_mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos) ;
    static return_t scc_lseek(int fd, off_t offset, int whence) ;
    static return_t scc_truncate(char *path, off_t length) ;
    static return_t scc_ftruncate(int fd, off_t length) ;
    static return_t scc_sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static return_t scc_mlock(caddr_t addr, size_t len) ;
    static return_t scc_munlock(caddr_t addr, size_t len) ;
    static return_t scc_undelete(user_addr_t path) ;
    static return_t scc_open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode) ;
    static return_t scc_getattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_setattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_getdirentriesattr(int fd, struct attrlist *alist, void *buffer, size_t buffersize, u_long *count, u_long *basep, u_long *newstate, u_long options) ;
    static return_t scc_exchangedata(const char *path1, const char *path2, u_long options) ;
    static return_t scc_searchfs(const char *path, struct fssearchblock *searchblock, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct searchstate *state) ;
    static return_t scc_delete(user_addr_t path) ;
    static return_t scc_copyfile(char *from, char *to, int mode, int flags) ;
    static return_t scc_fgetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_fsetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_poll(struct pollfd *fds, u_int nfds, int timeout) ;
    static return_t scc_watchevent(struct eventreq *u_req, int u_eventmask) ;
    static return_t scc_waitevent(struct eventreq *u_req, struct timeval *tv) ;
    static return_t scc_modwatch(struct eventreq *u_req, int u_eventmask) ;
    static return_t scc_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_removexattr(user_addr_t path, user_addr_t attrname, int options) ;
    static return_t scc_fremovexattr(int fd, user_addr_t attrname, int options) ;
    static return_t scc_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize, int options) ;
    static return_t scc_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options) ;
    static return_t scc_fsctl(const char *path, u_long cmd, caddr_t data, u_int options) ;
    static return_t scc_initgroups(u_int gidsetsize, gid_t *gidset, int gmuid) ;
    static return_t scc_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *adesc, char **argv, char **envp) ;
    static return_t scc_ffsctl(int fd, u_long cmd, caddr_t data, u_int options) ;
    static return_t scc_nfsclnt(int flag, caddr_t argp) ;
    static return_t scc_fhopen(const struct fhandle *u_fhp, int flags) ;
    static return_t scc_minherit(void *addr, size_t len, int inherit) ;
    static return_t scc_semsys(u_int which, int a2, int a3, int a4, int a5) ;
    static return_t scc_msgsys(u_int which, int a2, int a3, int a4, int a5) ;
    static return_t scc_shmsys(u_int which, int a2, int a3, int a4) ;
    static return_t scc_semctl(int semid, int semnum, int cmd, user_semun_t arg) ;
    static return_t scc_semget(key_t key, int	nsems, int semflg) ;
    static return_t scc_semop(int semid, struct sembuf *sops, int nsops) ;
    static return_t scc_msgctl(int msqid, int cmd, struct	msqid_ds *buf) ;
    static return_t scc_msgget(key_t key, int msgflg) ;
    static return_t scc_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static return_t scc_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static return_t scc_shmat(int shmid, void *shmaddr, int shmflg) ;
    static return_t scc_shmctl(int shmid, int cmd, struct shmid_ds *buf) ;
    static return_t scc_shmdt(void *shmaddr) ;
    static return_t scc_shmget(key_t key, size_t size, int shmflg) ;
    static return_t scc_shm_open(const char *name, int oflag, int mode) ;
    static return_t scc_shm_unlink(const char *name) ;
    static return_t scc_sem_open(const char *name, int oflag, int mode, int value) ;
    static return_t scc_sem_close(sem_t *sem) ;
    static return_t scc_sem_unlink(const char *name) ;
    static return_t scc_sem_wait(sem_t *sem) ;
    static return_t scc_sem_trywait(sem_t *sem) ;
    static return_t scc_sem_post(sem_t *sem) ;
    static return_t scc_sysctlbyname(const char *name, size_t namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static return_t scc_open_extended(user_addr_t path, int flags, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_umask_extended(int newmask, user_addr_t xsecurity) ;
    static return_t scc_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_chmod_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_fchmod_extended(int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_access_extended(user_addr_t entries, size_t size, user_addr_t results, uid_t uid) ;
    static return_t scc_settid(uid_t uid, gid_t gid) ;
    static return_t scc_gettid(uid_t *uidp, gid_t *gidp) ;
    static return_t scc_setsgroups(int setlen, user_addr_t guidset) ;
    static return_t scc_getsgroups(user_addr_t setlen, user_addr_t guidset) ;
    static return_t scc_setwgroups(int setlen, user_addr_t guidset) ;
    static return_t scc_getwgroups(user_addr_t setlen, user_addr_t guidset) ;
    static return_t scc_mkfifo_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_mkdir_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_identitysvc(int opcode, user_addr_t message) ;
    static return_t scc_shared_region_check_np(uint64_t *start_address) ;
    static return_t scc_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored, uint32_t *pages_reclaimed) ;
    static return_t scc_psynch_rw_longrdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_yieldwrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_mutexwait(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_mutexdrop(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex,  uint64_t mugen, uint64_t tid) ;
    static return_t scc_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex,  uint64_t mugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec) ;
    static return_t scc_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_unlock2(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_getsid(pid_t pid) ;
    static return_t scc_settid_with_pid(pid_t pid, int assume) ;
    static return_t scc_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags) ;
    static return_t scc_aio_fsync(int op, user_addr_t aiocbp) ;
    static return_t scc_aio_return(user_addr_t aiocbp) ;
    static return_t scc_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static return_t scc_aio_cancel(int fd, user_addr_t aiocbp) ;
    static return_t scc_aio_error(user_addr_t aiocbp) ;
    static return_t scc_aio_read(user_addr_t aiocbp) ;
    static return_t scc_aio_write(user_addr_t aiocbp) ;
    static return_t scc_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp) ;
    static return_t scc_iopolicysys(int cmd, void *arg) ;
    static return_t scc_process_policy(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, pid_t target_pid, uint64_t target_threadid) ;
    static return_t scc_mlockall(int how) ;
    static return_t scc_munlockall(int how) ;
    static return_t scc_issetugid(void) ;
    static return_t scc___pthread_kill(int thread_port, int sig) ;
    static return_t scc___pthread_sigmask(int how, user_addr_t set, user_addr_t oset) ;
    static return_t scc___sigwait(user_addr_t set, user_addr_t sig) ;
    static return_t scc___disable_threadsignal(int value) ;
    static return_t scc___pthread_markcancel(int thread_port) ;
    static return_t scc___pthread_canceled(int  action) ;
    static return_t scc___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static return_t scc_proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) ;
    static return_t scc_sendfile(int fd, int s, off_t offset, off_t *nbytes, struct sf_hdtr *hdtr, int flags) ;
    static return_t scc_stat64(user_addr_t path, user_addr_t ub) ;
    static return_t scc_fstat64(int fd, user_addr_t ub) ;
    static return_t scc_lstat64(user_addr_t path, user_addr_t ub) ;
    static return_t scc_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_getdirentries64(int fd, void *buf, user_size_t bufsize, off_t *position) ;
    static return_t scc_statfs64(char *path, void *buf) ;
    static return_t scc_fstatfs64(int fd, void *buf) ;
    static return_t scc_getfsstat64(user_addr_t buf, int bufsize, int flags) ;
    static return_t scc___pthread_chdir(user_addr_t path) ;
    static return_t scc___pthread_fchdir(int fd) ;
    static return_t scc_audit(void *record, int length) ;
    static return_t scc_auditon(int cmd, void *data, int length) ;
    static return_t scc_getauid(au_id_t *auid) ;
    static return_t scc_setauid(au_id_t *auid) ;
    static return_t scc_getaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static return_t scc_setaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static return_t scc_auditctl(char *path) ;
    static return_t scc_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack, user_addr_t pthread, uint32_t flags) ;
    static return_t scc_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port, uint32_t sem) ;
    static return_t scc_kqueue(void) ;
    static return_t scc_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout) ;
    static return_t scc_lchown(user_addr_t path, uid_t owner, gid_t group) ;
    static return_t scc_stack_snapshot(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset) ;
    static return_t scc_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset) ;
    static return_t scc_workq_open(void) ;
    static return_t scc_workq_kernreturn(int options, user_addr_t item, int affinity, int prio) ;
    static return_t scc_kevent64(int fd, const struct kevent64_s *changelist, int nchanges, struct kevent64_s *eventlist, int nevents, unsigned int flags, const struct timespec *timeout) ;
    static return_t scc___old_semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static return_t scc___old_semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static return_t scc_thread_selfid(void) ;
    static return_t scc_ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3) ;
    static return_t scc___mac_execve(char *fname, char **argp, char **envp, mac_t mac_p) ;
    static return_t scc___mac_get_file(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_set_file(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_get_link(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_set_link(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_get_proc(mac_t mac_p) ;
    static return_t scc___mac_set_proc(mac_t mac_p) ;
    static return_t scc___mac_get_fd(int fd, mac_t mac_p) ;
    static return_t scc___mac_set_fd(int fd, mac_t mac_p) ;
    static return_t scc___mac_get_pid(pid_t pid, mac_t mac_p) ;
    static return_t scc___mac_get_lcid(pid_t lcid, mac_t mac_p) ;
    static return_t scc___mac_get_lctx(mac_t mac_p) ;
    static return_t scc___mac_set_lctx(mac_t mac_p) ;
    static return_t scc_setlcid(pid_t pid, pid_t lcid) ;
    static return_t scc_getlcid(pid_t pid) ;
    static return_t scc_read_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_write_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_open_nocancel(user_addr_t path, int flags, int mode) ;
    static return_t scc_close_nocancel(int fd) ;
    static return_t scc_wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static return_t scc_recvmsg_nocancel(int s, struct msghdr *msg, int flags) ;
    static return_t scc_sendmsg_nocancel(int s, caddr_t msg, int flags) ;
    static return_t scc_recvfrom_nocancel(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static return_t scc_accept_nocancel(int s, caddr_t name, socklen_t	*anamelen) ;
    static return_t scc_msync_nocancel(caddr_t addr, size_t len, int flags) ;
    static return_t scc_fcntl_nocancel(int fd, int cmd, long arg) ;
    static return_t scc_select_nocancel(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static return_t scc_fsync_nocancel(int fd) ;
    static return_t scc_connect_nocancel(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_sigsuspend_nocancel(sigset_t mask) ;
    static return_t scc_readv_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_writev_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_sendto_nocancel(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static return_t scc_pread_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_pwrite_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_waitid_nocancel(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static return_t scc_poll_nocancel(struct pollfd *fds, u_int nfds, int timeout) ;
    static return_t scc_msgsnd_nocancel(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static return_t scc_msgrcv_nocancel(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static return_t scc_sem_wait_nocancel(sem_t *sem) ;
    static return_t scc_aio_suspend_nocancel(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static return_t scc___sigwait_nocancel(user_addr_t set, user_addr_t sig) ;
    static return_t scc___semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static return_t scc___mac_mount(char *type, char *path, int flags, caddr_t data, mac_t mac_p) ;
    static return_t scc___mac_get_mount(char *path, mac_t mac_p) ;
    static return_t scc___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize, int flags) ;
    static return_t scc_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid) ;
    static return_t scc_audit_session_self(void) ;
    static return_t scc_audit_session_join(mach_port_name_t port) ;
    static return_t scc_fileport_makeport(int fd, user_addr_t portnamep) ;
    static return_t scc_fileport_makefd(mach_port_name_t port) ;
    static return_t scc_audit_session_port(au_asid_t asid, user_addr_t portnamep) ;
    static return_t scc_pid_suspend(int pid) ;
    static return_t scc_pid_resume(int pid) ;
    static return_t scc_shared_region_map_and_slide_np(int fd, uint32_t count, const struct shared_file_mapping_np *mappings, uint32_t slide, uint64_t* slide_start, uint32_t slide_size) ;
    static return_t scc_kas_info(int selector, void *value, size_t *size) ;
    static return_t scc_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize) ;
    static return_t scc_guarded_open_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int mode) ;
    static return_t scc_guarded_close_np(int fd, const guardid_t *guard) ;
    static return_t scc_guarded_kqueue_np(const guardid_t *guard, u_int guardflags) ;
    static return_t scc_change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags, const guardid_t *nguard, u_int nguardflags, int *fdflagsp) ;
    static return_t scc_proc_rlimit_control(pid_t pid, int flavor, void *arg) ;
    static return_t scc_connectx(int s, struct sockaddr *src, socklen_t srclen, struct sockaddr *dsts, socklen_t dstlen, uint32_t ifscope, associd_t aid, connid_t *cid) ;
    static return_t scc_disconnectx(int s, associd_t aid, connid_t cid) ;
    static return_t scc_peeloff(int s, associd_t aid) ;
    static return_t scc_socket_delegate(int domain, int type, int protocol, pid_t epid) ;
    static return_t scc_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval, uint64_t leeway, uint64_t arg4, uint64_t arg5) ;
    static return_t scc_proc_uuid_policy(uint32_t operation, uuid_t uuid, size_t uuidlen, uint32_t flags) ;
    static return_t scc_memorystatus_get_level(user_addr_t level) ;
    static return_t scc_system_override(uint64_t timeout, uint64_t flags) ;
    static return_t scc_vfs_purge(void) ;
    static return_t scc_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time, uint64_t *out_time) ;
    static return_t scc_sfi_pidctl(uint32_t operation, pid_t pid, uint32_t sfi_flags, uint32_t *out_sfi_flags) ;
    static return_t scc_necp_match_policy(uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result) ;
    static return_t scc_getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, uint64_t options) ;
    static return_t scc_openat(int fd, user_addr_t path, int flags, int mode) ;
    static return_t scc_openat_nocancel(int fd, user_addr_t path, int flags, int mode) ;
    static return_t scc_renameat(int fromfd, char *from, int tofd, char *to) ;
    static return_t scc_faccessat(int fd, user_addr_t path, int amode, int flag) ;
    static return_t scc_fchmodat(int fd, user_addr_t path, int mode, int flag) ;
    static return_t scc_fchownat(int fd, user_addr_t path, uid_t uid,gid_t gid, int flag) ;
    static return_t scc_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static return_t scc_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static return_t scc_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag) ;
    static return_t scc_unlinkat(int fd, user_addr_t path, int flag) ;
    static return_t scc_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize) ;
    static return_t scc_symlinkat(user_addr_t *path1, int fd, user_addr_t path2) ;
    static return_t scc_mkdirat(int fd, user_addr_t path, int mode) ;
    static return_t scc_getattrlistat(int fd, const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_proc_trace_log(pid_t pid, uint64_t uniqueid) ;
    static return_t scc_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) ;
    static return_t scc_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags) ;
    static return_t scc_recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static return_t scc_sendmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static return_t scc_thread_selfusage(void) ;
    static return_t scc_guarded_open_dprotected_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int dpclass, int dpflags, int mode) ;
    static return_t scc_guarded_write_np(int fd, const guardid_t *guard, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_guarded_pwrite_np(int fd, const guardid_t *guard, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_guarded_writev_np(int fd, const guardid_t *guard, struct iovec *iovp, u_int iovcnt) ;
