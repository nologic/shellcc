import re

def parsesyscallsmaster(filename):
        '''
        parsesyscallsmaster: filename

        Parses the syscalls.master file to retrieve names and arguments
        for syscalls.
        '''

        syscallinfo = {}

        syscalldef_re = re.compile('(?P<num>[0-9]+)\s+([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\s+\{\s+([a-zA-Z0-9_]+)\s+([a-zA-Z0-9_]+)\s*\(([^)]+)\)')

        try:
                with open(filename) as f:
                        for line in f:
                                m = syscalldef_re.match(line)
                                if m:
                                        num = int(m.group(1))
                                        name = m.group(5)
                                        params = m.group(6)
                                        if not syscallinfo.has_key(num):
                                                syscallinfo[num] = { "name" : name, "params" : params }
                                        else:
                                                # Overwrite if not nosys
                                                if name != "nosys":
                                                        syscallinfo[num] = { "name" : name, "params" : params }
        except IOError, err:
                pass

        return syscallinfo

"""
struct syscallname {
    int nr;
    const char *name;
    const char *format;
    void (*call)(const struct syscallname *,
                 abi_long, abi_long, abi_long,
                 abi_long, abi_long, abi_long);
    void (*result)(const struct syscallname *, abi_long);
};
"""

syscalls = parsesyscallsmaster("syscalls_xnu10.10.master")

for nr in syscalls.keys():
    callinfo = syscalls[nr]

    if(callinfo['name'] == "nosys" or callinfo['name'] == "enosys"):
        # skip placeholders
        continue

    params = [ [a for a in arg.replace('*', '').split(' ') if len(a) > 0][-1] for arg in callinfo['params'].split(',')]
    paramCount = len(params)

    if(params[0] != "void"):
        params = "(uint64_t)" + ", (uint64_t)".join(params) + (", %d" % nr);
    else:
        paramCount = 0
        params = "%d" % nr

    exec_call = """
    static int scc_%s(%s) {
        return scc_syscall%d(%s);
    }
    """ % (callinfo['name'], callinfo['params'], paramCount, params)

    print exec_call

# grep static syscalls_xnu10.10.c | sed 's/{/;/g' > syscalls_xnu10.10.h




