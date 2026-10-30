"""Linux x86-64 image-child policy. Install before native imports and input.

Landlock confines file contents; a seccomp allowlist restricts system calls.
This does not replace container limits, kernel updates or independent review.
UAPI references and deployment requirements: docs/bildarbetare.md.
"""
import ctypes
import errno
import os
from pathlib import Path
import stat
import sys


class ConfinementUnavailable(OSError):
    pass


class Ruleset(ctypes.Structure):
    _fields_ = [('handled_access_fs', ctypes.c_uint64)]


class PathRule(ctypes.Structure):
    _pack_ = 1
    _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]


class Instruction(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_ushort), ('instructions', ctypes.POINTER(Instruction))]


# Linux x86-64 UAPI, not x32/i386. Files opened below remain subject to Landlock.
# No networking, process creation/inspection, exec, io_uring, filesystem mutation,
# module/BPF loading, namespace changes or privilege/credential changes.
SYSCALLS = {
    'read': 0, 'write': 1, 'open': 2, 'close': 3, 'stat': 4, 'fstat': 5,
    'lstat': 6, 'poll': 7, 'lseek': 8, 'mmap': 9, 'mprotect': 10,
    'munmap': 11, 'brk': 12, 'rt_sigaction': 13, 'rt_sigprocmask': 14,
    'rt_sigreturn': 15, 'pread64': 17, 'readv': 19, 'writev': 20,
    'access': 21, 'select': 23, 'sched_yield': 24, 'mremap': 25,
    'mincore': 27, 'madvise': 28, 'dup': 32, 'dup2': 33,
    'nanosleep': 35, 'getpid': 39, 'exit': 60, 'uname': 63,
    'getcwd': 79, 'readlink': 89, 'gettimeofday': 96, 'getrlimit': 97,
    'getrusage': 98, 'sysinfo': 99, 'times': 100, 'getuid': 102,
    'getgid': 104, 'geteuid': 107, 'getegid': 108, 'getppid': 110,
    'sigaltstack': 131, 'arch_prctl': 158, 'gettid': 186,
    'futex': 202, 'sched_getaffinity': 204, 'getdents64': 217,
    'set_tid_address': 218, 'clock_gettime': 228, 'clock_getres': 229,
    'clock_nanosleep': 230, 'exit_group': 231, 'openat': 257,
    'newfstatat': 262, 'readlinkat': 267, 'faccessat': 269,
    'set_robust_list': 273, 'get_robust_list': 274, 'dup3': 292,
    'getrandom': 318, 'membarrier': 324, 'statx': 332, 'rseq': 334,
    'close_range': 436, 'faccessat2': 439,
}
ALLOW, DENY, KILL = 0x7fff0000, 0x50000 | errno.EPERM, 0x80000000
LD, JEQ, RET = 0x20, 0x15, 0x06


def syscall_filter(pid):
    # seccomp_data: nr at 0, arch at 4, args[0] at 16 (little endian).
    instructions = [(LD, 0, 0, 4), (JEQ, 1, 0, 0xc000003e), (RET, 0, 0, KILL),
                    (LD, 0, 0, 0)]
    for number in sorted(SYSCALLS.values()):
        instructions += [(JEQ, 0, 1, number), (RET, 0, 0, ALLOW)]

    def argument_rule(number, argument, values):
        body = [(LD, 0, 0, 20 + argument * 8), (JEQ, 1, 0, 0),
                (RET, 0, 0, DENY), (LD, 0, 0, 16 + argument * 8)]
        for value in values:
            body += [(JEQ, 0, 1, value), (RET, 0, 0, ALLOW)]
        body += [(RET, 0, 0, DENY)]
        instructions.extend([(JEQ, 0, len(body), number)] + body)

    # Only the child's thread group may be signalled. No kill/tkill/queue calls.
    argument_rule(234, 0, (pid,))  # tgkill
    # Read-only protection queries; cannot turn dumpability back on.
    argument_rule(157, 0, (3, 21, 39))  # GET_DUMPABLE, GET_SECCOMP, GET_NO_NEW_PRIVS
    # FD bookkeeping, not leases, signal ownership or arbitrary commands.
    argument_rule(72, 1, (0, 1, 2, 3, 4, 1030))  # fcntl
    # prlimit64(0, resource, NULL, old_limit): read own limits only.
    query = [(LD, 0, 0, offset) for offset in (16, 20, 32, 36)]
    body = []
    for instruction in query:
        body += [instruction, (JEQ, 1, 0, 0), (RET, 0, 0, DENY)]
    body += [(RET, 0, 0, ALLOW)]
    instructions.extend([(JEQ, 0, len(body), 302)] + body)
    instructions.append((RET, 0, 0, DENY))
    return instructions


def read_paths():
    """Fixed read policy; no data directories or arbitrary PYTHONPATH grants."""
    source = Path(__file__).resolve().parent
    paths = [Path('/usr/lib'), Path('/usr/local/lib'), Path('/lib'),
             Path(sys.base_prefix) / 'lib', Path(sys.prefix) / 'lib',
             Path('/opt/openid-opencv'),
             Path('/etc/ld.so.cache'), Path('/etc/localtime'),
             Path('/dev/null'), Path('/dev/urandom'),
             Path('/proc/cpuinfo'), Path('/proc/meminfo'),
             Path(f'/proc/{os.getpid()}/status'),
             Path('/sys/devices/system/cpu')]
    # Individual source files, not a grant over the whole working directory.
    paths.extend(path for path in source.glob('*.py')
                 if stat.S_ISREG(path.lstat().st_mode))
    for name in ('models', 'vendor'):
        path = source / name
        if path.exists():
            if not path.resolve().is_relative_to(source):
                raise ConfinementUnavailable('image worker code path escapes source')
            paths.append(path)
    return sorted({path.resolve() for path in paths if path.exists()})


def _landlock(libc, paths):
    syscall = libc.syscall
    syscall.restype = ctypes.c_long
    abi = syscall(444, 0, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 3:
        raise ConfinementUnavailable('image worker requires Landlock ABI 3')
    # All filesystem operations through ABI 3; add device ioctls with ABI 5.
    ruleset = Ruleset((1 << (16 if abi >= 5 else 15)) - 1)
    fd = syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise ConfinementUnavailable('image worker filesystem policy unavailable')
    try:
        for path in paths:
            parent = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                access = 4 | (8 if stat.S_ISDIR(os.fstat(parent).st_mode) else 0)
                rule = PathRule(access, parent)
                if syscall(445, fd, 1, ctypes.byref(rule), 0) != 0:
                    raise ConfinementUnavailable('image worker read policy rejected')
            finally:
                os.close(parent)
        if syscall(446, fd, 0) != 0:
            raise ConfinementUnavailable('image worker filesystem policy rejected')
    finally:
        os.close(fd)


def confine_image_worker():
    """Irreversible child-only policy. macOS development is explicitly unconfined."""
    if sys.platform != 'linux':
        return False
    if os.uname().machine != 'x86_64' or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ConfinementUnavailable('unsupported image worker architecture')
    if len(os.listdir('/proc/self/task')) != 1:
        raise ConfinementUnavailable('image worker must start single threaded')
    # Popen(close_fds=True) is mandatory; do not let pre-opened FDs bypass policy.
    for name in os.listdir('/proc/self/fd'):
        if int(name) <= 2:
            continue
        try:
            os.fstat(int(name))
        except OSError as error:
            if error.errno == errno.EBADF:
                continue  # The closed listdir descriptor.
            raise
        raise ConfinementUnavailable('unexpected image worker descriptor')
    paths = read_paths()
    instructions = syscall_filter(os.getpid())
    filters = (Instruction * len(instructions))(*(Instruction(*line) for line in instructions))
    program = Program(len(filters), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.restype = ctypes.c_int
    # Fixed-width arguments matter for variadic libc entrypoints.
    prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    if prctl(38, 1, 0, 0, 0) != 0 or prctl(39, 0, 0, 0, 0) != 1:
        raise ConfinementUnavailable('image worker no-new-privileges unavailable')
    _landlock(libc, paths)
    if prctl(22, 2, ctypes.addressof(program), 0, 0) != 0 or prctl(21, 0, 0, 0, 0) != 2:
        raise ConfinementUnavailable('image worker syscall policy unavailable')
    return True
