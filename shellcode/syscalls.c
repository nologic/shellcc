// to be included at the bottom of the shellcode main file.

#define SYS_CALL_ASM \
		"svc 0x80;\n" \
		"neg x1, x0;\n" \
		"csel x0, x0, x1, cc;\n" 

static uint64_t scc_syscall0(uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0");

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_num));

	return _arg1;
}

static uint64_t scc_syscall1(uint64_t arg1, 
						 uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_num));

	return _arg1;
}

static uint64_t scc_syscall2(uint64_t arg1, uint64_t arg2, uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_num)
		:"x0");

	return arg1;
}

static uint64_t scc_syscall3(uint64_t arg1, uint64_t arg2, uint64_t arg3, 
						 uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_num));

	return _arg1;
}

static uint64_t scc_syscall4(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, 
						 uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;
	register uint64_t _arg4 asm("x3") = arg4;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_num));

	return _arg1;
}

static uint64_t scc_syscall5(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;
	register uint64_t _arg4 asm("x3") = arg4;
	register uint64_t _arg5 asm("x4") = arg5;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_num));

	return _arg1;
}

static uint64_t scc_syscall6(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;
	register uint64_t _arg4 asm("x3") = arg4;
	register uint64_t _arg5 asm("x4") = arg5;
	register uint64_t _arg6 asm("x5") = arg6;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_num));

	return _arg1;
}

static uint64_t scc_syscall7(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;
	register uint64_t _arg4 asm("x3") = arg4;
	register uint64_t _arg5 asm("x4") = arg5;
	register uint64_t _arg6 asm("x5") = arg6;
	register uint64_t _arg7 asm("x6") = arg7;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_num));

	return _arg1;
}

static uint64_t scc_syscall8(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8,uint64_t num) {
	register uint64_t _num asm("x16") = num;
	register uint64_t _arg1 asm("x0") = arg1;
	register uint64_t _arg2 asm("x1") = arg2;
	register uint64_t _arg3 asm("x2") = arg3;
	register uint64_t _arg4 asm("x3") = arg4;
	register uint64_t _arg5 asm("x4") = arg5;
	register uint64_t _arg6 asm("x5") = arg6;
	register uint64_t _arg7 asm("x6") = arg7;
	register uint64_t _arg8 asm("x7") = arg8;

	__asm__(
		SYS_CALL_ASM
		:"=r"(_arg1)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_arg8),"r"(_num));

	return _arg1;
}