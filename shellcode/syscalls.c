// to be included at the bottom of the shellcode main file.

#ifdef __x86_64
// set up parameters and calls for __x86_64

#define REG_ARG1 "rdi"
#define REG_SYSNUM "rax"
#define REG_SYSRET "rax"

#define DECL_ARG(name, reg)      register uint64_t name asm(reg)
#define COPY_ARG(dest, src, reg) DECL_ARG(dest, reg) = src

#define COPY_SYSNUM(dest, src) COPY_ARG(dest, src, REG_SYSNUM)
#define COPY_ARG1(dest, src)   COPY_ARG(dest, src, "rdi")
#define COPY_ARG2(dest, src)   COPY_ARG(dest, src, "rsi")
#define COPY_ARG3(dest, src)   COPY_ARG(dest, src, "rdx")
#define COPY_ARG4(dest, src)   COPY_ARG(dest, src, "r10")
#define COPY_ARG5(dest, src)   COPY_ARG(dest, src, "r8")
#define COPY_ARG6(dest, src)   COPY_ARG(dest, src, "r9")

// These are not used by the kernel, we include them to get the 
//   functions to compile.
#define COPY_ARG7(dest, src)   COPY_ARG(dest, src, "rcx")
#define COPY_ARG8(dest, src)   COPY_ARG(dest, src, "r11")

#define SCRATCH_REGS "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"

// .bytes are jnb +3
#define SYS_CALL_ASM \
		"syscall;\n"  \
		".byte 0x73; .byte 0x03;\n" \
		"negq %%rax;\n" 

#elif __arm64
// set up parameters and calls for __arm64

#define REG_ARG1 "x0"
#define REG_SYSNUM "x16"
#define REG_SYSRET "x0"

#define DECL_ARG(name, reg)      register uint64_t name asm(reg)
#define COPY_ARG(dest, src, reg) DECL_ARG(dest, reg) = src

#define COPY_SYSNUM(dest, src) COPY_ARG(dest, src, REG_SYSNUM)
#define COPY_ARG1(dest, src)   COPY_ARG(dest, src, "x0")
#define COPY_ARG2(dest, src)   COPY_ARG(dest, src, "x1")
#define COPY_ARG3(dest, src)   COPY_ARG(dest, src, "x2")
#define COPY_ARG4(dest, src)   COPY_ARG(dest, src, "x3")
#define COPY_ARG5(dest, src)   COPY_ARG(dest, src, "x4")
#define COPY_ARG6(dest, src)   COPY_ARG(dest, src, "x5")
#define COPY_ARG7(dest, src)   COPY_ARG(dest, src, "x6")
#define COPY_ARG8(dest, src)   COPY_ARG(dest, src, "x7")

#define SCRATCH_REGS "x16", "x17"

#define SYS_CALL_ASM \
		"svc 0x80;\n" \
		"neg x1, x0;\n" \
		"csel x0, x0, x1, cc;\n" 

#elif __mips
// set up parameters and calls for MIPS

#define REG_ARG1 "a0"
#define REG_SYSNUM "v0"
#define REG_SYSRET "v0"
#define ARG_TYPE uint32_t

#define DECL_ARG(name, reg)      register ARG_TYPE name asm(reg)
#define COPY_ARG(dest, src, reg) DECL_ARG(dest, reg) = src

#define COPY_SYSNUM(dest, src) COPY_ARG(dest, src, REG_SYSNUM)
#define COPY_ARG1(dest, src)   COPY_ARG(dest, src, "a0")
#define COPY_ARG2(dest, src)   COPY_ARG(dest, src, "a1")
#define COPY_ARG3(dest, src)   COPY_ARG(dest, src, "a2")
#define COPY_ARG4(dest, src)   COPY_ARG(dest, src, "a3")
#define COPY_ARG5(dest, src)   COPY_ARG(dest, src, "a4")
#define COPY_ARG6(dest, src)   COPY_ARG(dest, src, "a5")
#define COPY_ARG7(dest, src)   COPY_ARG(dest, src, "a6")
#define COPY_ARG8(dest, src)   COPY_ARG(dest, src, "a7")

#define SCRATCH_REGS "t0"

#define SYS_CALL_ASM \
    "syscall;\n" /*\
    "beqz $a3, 0x8;\n" \
    "negu $v0, $v0;\n" \
    "move $v0, $v0;\n"*/

#else
	#error "Unsupported architecture"
#endif

static uint64_t scc_syscall0(uint64_t num) {
	COPY_SYSNUM(_num, num);
	DECL_ARG(_arg1, REG_ARG1);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall1(uint64_t arg1, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);

	DECL_ARG(_ret, REG_SYSRET);

    asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall2(uint64_t arg1, uint64_t arg2, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall3(uint64_t arg1, uint64_t arg2, uint64_t arg3, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall4(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall5(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall6(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall7(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);
	COPY_ARG7(_arg7, arg7);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall8(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8,uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);
	COPY_ARG7(_arg7, arg7);
	COPY_ARG8(_arg8, arg8);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_arg8),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}