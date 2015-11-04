// https://gcc.gnu.org/onlinedocs/gcc-4.0.4/gcc/Function-Attributes.html

#ifndef SHELLCODE_H
#define SHELLCODE_H

#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef __arm64
#define ASM_BREAKPOINT __asm__("BRK #3");
#elif __x86_64
#define ASM_BREAKPOINT __asm__("int3");
#elif
#error "Unsupported architecture"
#endif

static uint64_t scc_syscall0(uint64_t num) ;
static uint64_t scc_syscall1(uint64_t arg1, uint64_t num) ;
static uint64_t scc_syscall2(uint64_t arg1, uint64_t arg2, uint64_t num);
static uint64_t scc_syscall3(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t num) ;
static uint64_t scc_syscall4(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t num) ;
static uint64_t scc_syscall5(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t num) ;
static uint64_t scc_syscall6(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t num) ;
static uint64_t scc_syscall7(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t num) ;
static uint64_t scc_syscall8(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t num) ;


#define PRE_CONDITION(reg, var) __asm__("mov %0, " reg : "=r"(var))

#endif