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

    __attribute__((noreturn)) static void scc_exit(int rval) ;
    static int scc_fork(void) ;
    static int scc_read(int fd, char* cbuf, user_size_t nbyte) ;
    static int scc_write(int fd, char* cbuf, user_size_t nbyte) ;
    static int scc_open(char* path, int flags, int mode) ;
    static int scc_close(int fd) ;
    static int scc_wait4(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static int scc_link(char* path, user_addr_t link) ;
    static int scc_unlink(char* path) ;
    static int scc_chdir(char* path) ;
    static int scc_fchdir(int fd) ;
    static int scc_mknod(char* path, int mode, int dev) ;
    static int scc_chmod(char* path, int mode) ;
    static int scc_chown(char* path, int uid, int gid) ;
    static int scc_getfsstat(char* buf, int bufsize, int flags) ;
    static int scc_getpid(void) ;
    static int scc_setuid(uid_t uid) ;
    static int scc_getuid(void) ;
    static int scc_geteuid(void) ;
    static int scc_ptrace(int req, pid_t pid, caddr_t addr, int data) ;
    static int scc_recvmsg(int s, struct msghdr *msg, int flags) ;
    static int scc_sendmsg(int s, caddr_t msg, int flags) ;
    static int scc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static int scc_accept(int s, caddr_t name, socklen_t	*anamelen) ;
    static int scc_getpeername(int fdes, caddr_t asa, socklen_t *alen) ;
    static int scc_getsockname(int fdes, caddr_t asa, socklen_t *alen) ;
    static int scc_access(char* path, int flags) ;
    static int scc_chflags(char *path, int flags) ;
    static int scc_fchflags(int fd, int flags) ;
    static int scc_sync(void) ;
    static int scc_kill(int pid, int signum, int posix) ;
    static int scc_getppid(void) ;
    static int scc_dup(u_int fd) ;
    static int scc_pipe(void) ;
    static int scc_getegid(void) ;
    static int scc_sigaction(int signum, struct __sigaction *nsa, struct sigaction *osa) ;
    static int scc_getgid(void) ;
    static int scc_sigprocmask(int how, user_addr_t mask, user_addr_t omask) ;
    static int scc_getlogin(char *namebuf, u_int namelen) ;
    static int scc_setlogin(char *namebuf) ;
    static int scc_acct(char *path) ;
    static int scc_sigpending(struct sigvec *osv) ;
    static int scc_sigaltstack(const stack_t *restrict ss, stack_t *restrict oss) ;
    static int scc_ioctl(int fd, u_long com, caddr_t data) ;
    static int scc_reboot(int opt, char *command) ;
    static int scc_revoke(char *path) ;
    static int scc_symlink(char *path, char *link) ;
    static int scc_readlink(char *path, char *buf, int count) ;
    static int scc_execve(char *fname, char **argp, char **envp) ;
    static int scc_umask(int newmask) ;
    static int scc_chroot(char* path) ;
    static int scc_msync(caddr_t addr, size_t len, int flags) ;
    static int scc_vfork(void) ;
    static int scc_munmap(caddr_t addr, size_t len) ;
    static int scc_mprotect(caddr_t addr, size_t len, int prot) ;
    static int scc_madvise(caddr_t addr, size_t len, int behav) ;
    static int scc_mincore(user_addr_t addr, user_size_t len, user_addr_t vec) ;
    static int scc_getgroups(u_int gidsetsize, gid_t *gidset) ;
    static int scc_setgroups(u_int gidsetsize, gid_t *gidset) ;
    static int scc_getpgrp(void) ;
    static int scc_setpgid(int pid, int pgid) ;
    static int scc_setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv) ;
    static int scc_swapon(void) ;
    static int scc_getitimer(u_int which, struct itimerval *itv) ;
    static int scc_getdtablesize(void) ;
    static int scc_dup2(u_int from, u_int to) ;
    static int scc_fcntl(int fd, int cmd, long arg) ;
    static int scc_select(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static int scc_fsync(int fd) ;
    static int scc_setpriority(int which, id_t who, int prio) ;
    static int scc_socket(int domain, int type, int protocol) ;
    static int scc_connect(int s, caddr_t name, socklen_t namelen) ;
    static int scc_getpriority(int which, id_t who) ;
    static int scc_bind(int s, caddr_t name, socklen_t namelen) ;
    static int scc_setsockopt(int s, int level, int name, caddr_t val, socklen_t valsize) ;
    static int scc_listen(int s, int backlog) ;
    static int scc_sigsuspend(sigset_t mask) ;
    static int scc_gettimeofday(struct timeval *tp, struct timezone *tzp) ;
    static int scc_getrusage(int who, struct rusage *rusage) ;
    static int scc_getsockopt(int s, int level, int name, caddr_t val, socklen_t *avalsize) ;
    static int scc_readv(int fd, struct iovec *iovp, u_int iovcnt) ;
    static int scc_writev(int fd, struct iovec *iovp, u_int iovcnt) ;
    static int scc_settimeofday(struct timeval *tv, struct timezone *tzp) ;
    static int scc_fchown(int fd, int uid, int gid) ;
    static int scc_fchmod(int fd, int mode) ;
    static int scc_setreuid(uid_t ruid, uid_t euid) ;
    static int scc_setregid(gid_t rgid, gid_t egid) ;
    static int scc_rename(char *from, char *to) ;
    static int scc_flock(int fd, int how) ;
    static int scc_mkfifo(char* path, int mode) ;
    static int scc_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static int scc_shutdown(int s, int how) ;
    static int scc_socketpair(int domain, int type, int protocol, int *rsv) ;
    static int scc_mkdir(char* path, int mode) ;
    static int scc_rmdir(char *path) ;
    static int scc_utimes(char *path, struct timeval *tptr) ;
    static int scc_futimes(int fd, struct timeval *tptr) ;
    static int scc_adjtime(struct timeval *delta, struct timeval *olddelta) ;
    static int scc_gethostuuid(unsigned char *uuid_buf, const struct timespec *timeoutp, int spi) ;
    static int scc_setsid(void) ;
    static int scc_getpgid(pid_t pid) ;
    static int scc_setprivexec(int flag) ;
    static int scc_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static int scc_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static int scc_nfssvc(int flag, caddr_t argp) ;
    static int scc_statfs(char *path, struct statfs *buf) ;
    static int scc_fstatfs(int fd, struct statfs *buf) ;
    static int scc_unmount(char* path, int flags) ;
    static int scc_getfh(char *fname, fhandle_t *fhp) ;
    static int scc_quotactl(const char *path, int cmd, int uid, caddr_t arg) ;
    static int scc_mount(char *type, char *path, int flags, caddr_t data) ;
    static int scc_csops(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize) ;
    static int scc_csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken) ;
    static int scc_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static int scc_kdebug_trace(int code, int arg1, int arg2, int arg3, int arg4, int arg5) ;
    static int scc_setgid(gid_t gid) ;
    static int scc_setegid(gid_t egid) ;
    static int scc_seteuid(uid_t euid) ;
    static int scc_sigreturn(void* *uctx, int infostyle) ;
    static int scc_chud(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) ;
    static int scc_fdatasync(int fd) ;
    static int scc_stat(user_addr_t path, user_addr_t ub) ;
    static int scc_fstat(int fd, user_addr_t ub) ;
    static int scc_lstat(user_addr_t path, user_addr_t ub) ;
    static int scc_pathconf(char *path, int name) ;
    static int scc_fpathconf(int fd, int name) ;
    static int scc_getrlimit(u_int which, struct rlimit *rlp) ;
    static int scc_setrlimit(u_int which, struct rlimit *rlp) ;
    static int scc_getdirentries(int fd, char *buf, u_int count, long *basep) ;
    static int scc_mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos) ;
    static int scc_lseek(int fd, off_t offset, int whence) ;
    static int scc_truncate(char *path, off_t length) ;
    static int scc_ftruncate(int fd, off_t length) ;
    static int scc_sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static int scc_mlock(caddr_t addr, size_t len) ;
    static int scc_munlock(caddr_t addr, size_t len) ;
    static int scc_undelete(user_addr_t path) ;
    static int scc_open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode) ;
    static int scc_getattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static int scc_setattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static int scc_getdirentriesattr(int fd, struct attrlist *alist, void *buffer, size_t buffersize, u_long *count, u_long *basep, u_long *newstate, u_long options) ;
    static int scc_exchangedata(const char *path1, const char *path2, u_long options) ;
    static int scc_searchfs(const char *path, struct fssearchblock *searchblock, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct searchstate *state) ;
    static int scc_delete(user_addr_t path) ;
    static int scc_copyfile(char *from, char *to, int mode, int flags) ;
    static int scc_fgetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static int scc_fsetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static int scc_poll(struct pollfd *fds, u_int nfds, int timeout) ;
    static int scc_watchevent(struct eventreq *u_req, int u_eventmask) ;
    static int scc_waitevent(struct eventreq *u_req, struct timeval *tv) ;
    static int scc_modwatch(struct eventreq *u_req, int u_eventmask) ;
    static int scc_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static int scc_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static int scc_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static int scc_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static int scc_removexattr(user_addr_t path, user_addr_t attrname, int options) ;
    static int scc_fremovexattr(int fd, user_addr_t attrname, int options) ;
    static int scc_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize, int options) ;
    static int scc_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options) ;
    static int scc_fsctl(const char *path, u_long cmd, caddr_t data, u_int options) ;
    static int scc_initgroups(u_int gidsetsize, gid_t *gidset, int gmuid) ;
    static int scc_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *adesc, char **argv, char **envp) ;
    static int scc_ffsctl(int fd, u_long cmd, caddr_t data, u_int options) ;
    static int scc_nfsclnt(int flag, caddr_t argp) ;
    static int scc_fhopen(const struct fhandle *u_fhp, int flags) ;
    static int scc_minherit(void *addr, size_t len, int inherit) ;
    static int scc_semsys(u_int which, int a2, int a3, int a4, int a5) ;
    static int scc_msgsys(u_int which, int a2, int a3, int a4, int a5) ;
    static int scc_shmsys(u_int which, int a2, int a3, int a4) ;
    static int scc_semctl(int semid, int semnum, int cmd, user_semun_t arg) ;
    static int scc_semget(key_t key, int	nsems, int semflg) ;
    static int scc_semop(int semid, struct sembuf *sops, int nsops) ;
    static int scc_msgctl(int msqid, int cmd, struct	msqid_ds *buf) ;
    static int scc_msgget(key_t key, int msgflg) ;
    static int scc_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static int scc_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static int scc_shmat(int shmid, void *shmaddr, int shmflg) ;
    static int scc_shmctl(int shmid, int cmd, struct shmid_ds *buf) ;
    static int scc_shmdt(void *shmaddr) ;
    static int scc_shmget(key_t key, size_t size, int shmflg) ;
    static int scc_shm_open(const char *name, int oflag, int mode) ;
    static int scc_shm_unlink(const char *name) ;
    static int scc_sem_open(const char *name, int oflag, int mode, int value) ;
    static int scc_sem_close(sem_t *sem) ;
    static int scc_sem_unlink(const char *name) ;
    static int scc_sem_wait(sem_t *sem) ;
    static int scc_sem_trywait(sem_t *sem) ;
    static int scc_sem_post(sem_t *sem) ;
    static int scc_sysctlbyname(const char *name, size_t namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static int scc_open_extended(user_addr_t path, int flags, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static int scc_umask_extended(int newmask, user_addr_t xsecurity) ;
    static int scc_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_chmod_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static int scc_fchmod_extended(int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static int scc_access_extended(user_addr_t entries, size_t size, user_addr_t results, uid_t uid) ;
    static int scc_settid(uid_t uid, gid_t gid) ;
    static int scc_gettid(uid_t *uidp, gid_t *gidp) ;
    static int scc_setsgroups(int setlen, user_addr_t guidset) ;
    static int scc_getsgroups(user_addr_t setlen, user_addr_t guidset) ;
    static int scc_setwgroups(int setlen, user_addr_t guidset) ;
    static int scc_getwgroups(user_addr_t setlen, user_addr_t guidset) ;
    static int scc_mkfifo_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static int scc_mkdir_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static int scc_identitysvc(int opcode, user_addr_t message) ;
    static int scc_shared_region_check_np(uint64_t *start_address) ;
    static int scc_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored, uint32_t *pages_reclaimed) ;
    static int scc_psynch_rw_longrdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_psynch_rw_yieldwrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_psynch_mutexwait(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static int scc_psynch_mutexdrop(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static int scc_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex,  uint64_t mugen, uint64_t tid) ;
    static int scc_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex,  uint64_t mugen, uint64_t tid, uint32_t flags) ;
    static int scc_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec) ;
    static int scc_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_psynch_rw_unlock2(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static int scc_getsid(pid_t pid) ;
    static int scc_settid_with_pid(pid_t pid, int assume) ;
    static int scc_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags) ;
    static int scc_aio_fsync(int op, user_addr_t aiocbp) ;
    static int scc_aio_return(user_addr_t aiocbp) ;
    static int scc_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static int scc_aio_cancel(int fd, user_addr_t aiocbp) ;
    static int scc_aio_error(user_addr_t aiocbp) ;
    static int scc_aio_read(user_addr_t aiocbp) ;
    static int scc_aio_write(user_addr_t aiocbp) ;
    static int scc_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp) ;
    static int scc_iopolicysys(int cmd, void *arg) ;
    static int scc_process_policy(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, pid_t target_pid, uint64_t target_threadid) ;
    static int scc_mlockall(int how) ;
    static int scc_munlockall(int how) ;
    static int scc_issetugid(void) ;
    static int scc___pthread_kill(int thread_port, int sig) ;
    static int scc___pthread_sigmask(int how, user_addr_t set, user_addr_t oset) ;
    static int scc___sigwait(user_addr_t set, user_addr_t sig) ;
    static int scc___disable_threadsignal(int value) ;
    static int scc___pthread_markcancel(int thread_port) ;
    static int scc___pthread_canceled(int  action) ;
    static int scc___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static int scc_proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) ;
    static int scc_sendfile(int fd, int s, off_t offset, off_t *nbytes, struct sf_hdtr *hdtr, int flags) ;
    static int scc_stat64(user_addr_t path, user_addr_t ub) ;
    static int scc_fstat64(int fd, user_addr_t ub) ;
    static int scc_lstat64(user_addr_t path, user_addr_t ub) ;
    static int scc_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static int scc_getdirentries64(int fd, void *buf, user_size_t bufsize, off_t *position) ;
    static int scc_statfs64(char *path, void *buf) ;
    static int scc_fstatfs64(int fd, void *buf) ;
    static int scc_getfsstat64(user_addr_t buf, int bufsize, int flags) ;
    static int scc___pthread_chdir(user_addr_t path) ;
    static int scc___pthread_fchdir(int fd) ;
    static int scc_audit(void *record, int length) ;
    static int scc_auditon(int cmd, void *data, int length) ;
    static int scc_getauid(au_id_t *auid) ;
    static int scc_setauid(au_id_t *auid) ;
    static int scc_getaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static int scc_setaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static int scc_auditctl(char *path) ;
    static int scc_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack, user_addr_t pthread, uint32_t flags) ;
    static int scc_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port, uint32_t sem) ;
    static int scc_kqueue(void) ;
    static int scc_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout) ;
    static int scc_lchown(user_addr_t path, uid_t owner, gid_t group) ;
    static int scc_stack_snapshot(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset) ;
    static int scc_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset) ;
    static int scc_workq_open(void) ;
    static int scc_workq_kernreturn(int options, user_addr_t item, int affinity, int prio) ;
    static int scc_kevent64(int fd, const struct kevent64_s *changelist, int nchanges, struct kevent64_s *eventlist, int nevents, unsigned int flags, const struct timespec *timeout) ;
    static int scc___old_semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static int scc___old_semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static int scc_thread_selfid(void) ;
    static int scc_ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3) ;
    static int scc___mac_execve(char *fname, char **argp, char **envp, mac_t mac_p) ;
    static int scc___mac_get_file(char *path_p, mac_t mac_p) ;
    static int scc___mac_set_file(char *path_p, mac_t mac_p) ;
    static int scc___mac_get_link(char *path_p, mac_t mac_p) ;
    static int scc___mac_set_link(char *path_p, mac_t mac_p) ;
    static int scc___mac_get_proc(mac_t mac_p) ;
    static int scc___mac_set_proc(mac_t mac_p) ;
    static int scc___mac_get_fd(int fd, mac_t mac_p) ;
    static int scc___mac_set_fd(int fd, mac_t mac_p) ;
    static int scc___mac_get_pid(pid_t pid, mac_t mac_p) ;
    static int scc___mac_get_lcid(pid_t lcid, mac_t mac_p) ;
    static int scc___mac_get_lctx(mac_t mac_p) ;
    static int scc___mac_set_lctx(mac_t mac_p) ;
    static int scc_setlcid(pid_t pid, pid_t lcid) ;
    static int scc_getlcid(pid_t pid) ;
    static int scc_read_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static int scc_write_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static int scc_open_nocancel(user_addr_t path, int flags, int mode) ;
    static int scc_close_nocancel(int fd) ;
    static int scc_wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static int scc_recvmsg_nocancel(int s, struct msghdr *msg, int flags) ;
    static int scc_sendmsg_nocancel(int s, caddr_t msg, int flags) ;
    static int scc_recvfrom_nocancel(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static int scc_accept_nocancel(int s, caddr_t name, socklen_t	*anamelen) ;
    static int scc_msync_nocancel(caddr_t addr, size_t len, int flags) ;
    static int scc_fcntl_nocancel(int fd, int cmd, long arg) ;
    static int scc_select_nocancel(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static int scc_fsync_nocancel(int fd) ;
    static int scc_connect_nocancel(int s, caddr_t name, socklen_t namelen) ;
    static int scc_sigsuspend_nocancel(sigset_t mask) ;
    static int scc_readv_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static int scc_writev_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static int scc_sendto_nocancel(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static int scc_pread_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static int scc_pwrite_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static int scc_waitid_nocancel(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static int scc_poll_nocancel(struct pollfd *fds, u_int nfds, int timeout) ;
    static int scc_msgsnd_nocancel(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static int scc_msgrcv_nocancel(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static int scc_sem_wait_nocancel(sem_t *sem) ;
    static int scc_aio_suspend_nocancel(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static int scc___sigwait_nocancel(user_addr_t set, user_addr_t sig) ;
    static int scc___semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static int scc___mac_mount(char *type, char *path, int flags, caddr_t data, mac_t mac_p) ;
    static int scc___mac_get_mount(char *path, mac_t mac_p) ;
    static int scc___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize, int flags) ;
    static int scc_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid) ;
    static int scc_audit_session_self(void) ;
    static int scc_audit_session_join(mach_port_name_t port) ;
    static int scc_fileport_makeport(int fd, user_addr_t portnamep) ;
    static int scc_fileport_makefd(mach_port_name_t port) ;
    static int scc_audit_session_port(au_asid_t asid, user_addr_t portnamep) ;
    static int scc_pid_suspend(int pid) ;
    static int scc_pid_resume(int pid) ;
    static int scc_shared_region_map_and_slide_np(int fd, uint32_t count, const struct shared_file_mapping_np *mappings, uint32_t slide, uint64_t* slide_start, uint32_t slide_size) ;
    static int scc_kas_info(int selector, void *value, size_t *size) ;
    static int scc_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize) ;
    static int scc_guarded_open_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int mode) ;
    static int scc_guarded_close_np(int fd, const guardid_t *guard) ;
    static int scc_guarded_kqueue_np(const guardid_t *guard, u_int guardflags) ;
    static int scc_change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags, const guardid_t *nguard, u_int nguardflags, int *fdflagsp) ;
    static int scc_proc_rlimit_control(pid_t pid, int flavor, void *arg) ;
    static int scc_connectx(int s, struct sockaddr *src, socklen_t srclen, struct sockaddr *dsts, socklen_t dstlen, uint32_t ifscope, associd_t aid, connid_t *cid) ;
    static int scc_disconnectx(int s, associd_t aid, connid_t cid) ;
    static int scc_peeloff(int s, associd_t aid) ;
    static int scc_socket_delegate(int domain, int type, int protocol, pid_t epid) ;
    static int scc_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval, uint64_t leeway, uint64_t arg4, uint64_t arg5) ;
    static int scc_proc_uuid_policy(uint32_t operation, uuid_t uuid, size_t uuidlen, uint32_t flags) ;
    static int scc_memorystatus_get_level(user_addr_t level) ;
    static int scc_system_override(uint64_t timeout, uint64_t flags) ;
    static int scc_vfs_purge(void) ;
    static int scc_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time, uint64_t *out_time) ;
    static int scc_sfi_pidctl(uint32_t operation, pid_t pid, uint32_t sfi_flags, uint32_t *out_sfi_flags) ;
    static int scc_necp_match_policy(uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result) ;
    static int scc_getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, uint64_t options) ;
    static int scc_openat(int fd, user_addr_t path, int flags, int mode) ;
    static int scc_openat_nocancel(int fd, user_addr_t path, int flags, int mode) ;
    static int scc_renameat(int fromfd, char *from, int tofd, char *to) ;
    static int scc_faccessat(int fd, user_addr_t path, int amode, int flag) ;
    static int scc_fchmodat(int fd, user_addr_t path, int mode, int flag) ;
    static int scc_fchownat(int fd, user_addr_t path, uid_t uid,gid_t gid, int flag) ;
    static int scc_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static int scc_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static int scc_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag) ;
    static int scc_unlinkat(int fd, user_addr_t path, int flag) ;
    static int scc_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize) ;
    static int scc_symlinkat(user_addr_t *path1, int fd, user_addr_t path2) ;
    static int scc_mkdirat(int fd, user_addr_t path, int mode) ;
    static int scc_getattrlistat(int fd, const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static int scc_proc_trace_log(pid_t pid, uint64_t uniqueid) ;
    static int scc_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) ;
    static int scc_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags) ;
    static int scc_recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static int scc_sendmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static int scc_thread_selfusage(void) ;
    static int scc_guarded_open_dprotected_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int dpclass, int dpflags, int mode) ;
    static int scc_guarded_write_np(int fd, const guardid_t *guard, user_addr_t cbuf, user_size_t nbyte) ;
    static int scc_guarded_pwrite_np(int fd, const guardid_t *guard, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static int scc_guarded_writev_np(int fd, const guardid_t *guard, struct iovec *iovp, u_int iovcnt) ;
