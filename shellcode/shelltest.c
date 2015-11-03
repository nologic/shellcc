#include "shellcode.h"
#include "xnu10.10/syscalls.h"
#include <unistd.h>

int main() {
	char buf[4096];
	char* name = "hello";

	// open file - doing a touch
	int fd = scc_open(name, O_RDONLY, 0);
	if(fd < 0) {
		scc_exit(fd);
	}

	int rd = scc_read(fd, buf, 20);
	if(rd < 0) {
		scc_exit(rd);
	}

	if(scc_write(STDOUT_FILENO, buf, rd) <= 0) {
		scc_exit(43);
	}

	buf[0] = 'a';
	buf[1] = '\n';
	if(scc_write(STDOUT_FILENO, buf, 2) <= 0) {
		scc_exit(46);
	}
	
	// end the process
	scc_exit(42);
}

#include "syscalls.c"
#include "xnu10.10/syscalls.c"

