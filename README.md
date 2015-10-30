# shellcc
SHELLCC is a build environment for making shellcode in C using GCC and other binary tool. It is meant to enable people with limited knowledge of assembly to write quality shellcode as well as bring code maintainability by using a high level language (specifically C).

Generally speaking shellcode does not require complex logic i.e. printfs, heavy abstraction or threading. These functions are left to the implants. Shellcode is expected to setup the environment and load the next stage of the attack. This step consists of doing cleanups and making a relatively small number of system call. For example, creating a reverse shell or downloading and executing the next stage implant. However, these functions can still be quite complex to write in assembly and it is hard to maintain them over time. Basically, all the reasons why we use compilers. 

The main reason is, of course, I was not very good at writting ARM assembly by hand. So, I needed some help from a compiler.

## Example
It is easy to see what this code, it calls out to an IP:PORT address and sends out a message. There is excessive error checking which would be really hard to do by hand. This code demonstrates how easy it is to build up the logic and let the compiler use its optimization magic in order to produce the best possible code.

```C
  int main() {
  	int sockfd;
  	struct sockaddr_in serv_addr;
  
  	sockfd = scc_socket(AF_INET, SOCK_STREAM, 0);
  	if (sockfd < 0) {
          scc_exit(43);
  	}
  
  	bzero((struct sockaddr *)&serv_addr,sizeof(serv_addr));
  	serv_addr.sin_family = AF_INET;
  	serv_addr.sin_addr.s_addr = SERVER_IP;
  	serv_addr.sin_port = htons(SERVER_PORT);
  
  	if(scc_connect(sockfd,(struct sockaddr *)&serv_addr,sizeof(serv_addr)) < 0) {
          scc_exit(44);
  	}
  
  	if(scc_write(sockfd, MESSAGE, MESSAGE_LEN) <= 0) {
  		scc_exit(45);
  	}
  	
  	scc_close(sockfd);
  
  	// end the process
  	scc_exit(42);
  }
```

The aboce C code produces a nice concise ARM64 ASM. It is likely that a dedicated person could produce an even more concise version, but that would take time better spent on finding vulnerabilities.

```Assembly
  0000000100007ecc	stp	x29, x30, [sp, #-16]!
  0000000100007ed0	mov	 x29, sp
  0000000100007ed4	sub	sp, sp, #16
  0000000100007ed8	movz	x2, #0
  0000000100007edc	orr	w8, wzr, #0x2
  0000000100007ee0	orr	w0, wzr, #0x2
  0000000100007ee4	orr	w1, wzr, #0x1
  0000000100007ee8	movz	w16, #0x61
  0000000100007eec	svc	#0x80
  0000000100007ef0	neg	 x1, x0
  0000000100007ef4	csel	x0, x0, x1, lo
  0000000100007ef8	tbz	w0, #31, 0x100007f04
  0000000100007efc	movz	w0, #0x2b
  0000000100007f00	bl	_scc_exit
  0000000100007f04	stp	 xzr, xzr, [sp]
  0000000100007f08	strb	w8, [sp, #1]
  0000000100007f0c	movz	w8, #0x501, lsl #16
  0000000100007f10	movk	w8, #0xa8c0
  0000000100007f14	str	w8, [sp, #4]
  0000000100007f18	movz	w9, #0xf27
  0000000100007f1c	sxtw	x8, w0
  0000000100007f20	strh	w9, [sp, #2]
  0000000100007f24	mov	 x1, sp
  0000000100007f28	orr	w2, wzr, #0x10
  0000000100007f2c	movz	w16, #0x62
  0000000100007f30	mov	 x0, x8
  0000000100007f34	svc	#0x80
  0000000100007f38	neg	 x1, x0
  0000000100007f3c	csel	x0, x0, x1, lo
  0000000100007f40	tbz	w0, #31, 0x100007f4c
  0000000100007f44	movz	w0, #0x2c
  0000000100007f48	bl	_scc_exit
  0000000100007f4c	adr	x1, #96 ; literal pool for: "Hello Dude\n"
  0000000100007f50	nop
  0000000100007f54	orr	w2, wzr, #0xc
  0000000100007f58	orr	w16, wzr, #0x4
  0000000100007f5c	mov	 x0, x8
  0000000100007f60	svc	#0x80
  0000000100007f64	neg	 x1, x0
  0000000100007f68	csel	x0, x0, x1, lo
  0000000100007f6c	cmp	 w0, #0
  0000000100007f70	b.gt	0x100007f7c
  0000000100007f74	movz	w0, #0x2d
  0000000100007f78	bl	_scc_exit
  0000000100007f7c	movz	w0, #0x2a
  0000000100007f80	bl	_scc_exit
  _scc_exit:
  0000000100007f84	stp	x29, x30, [sp, #-16]!
  0000000100007f88	mov	 x29, sp
  0000000100007f8c	sxtw	x0, w0
  0000000100007f90	orr	w1, wzr, #0x1
  0000000100007f94	bl	_scc_syscall1
  _scc_syscall1:
  0000000100007f98	mov	 x16, x1
  0000000100007f9c	svc	#0x80
  0000000100007fa0	neg	 x1, x0
  0000000100007fa4	csel	x0, x0, x1, lo
  0000000100007fa8	ret
```
----
[1] http://shell-storm.org/shellcode/
