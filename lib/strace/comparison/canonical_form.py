"""Canonical form for syscall representation.

This module exists for converting syscalls into a standardized form for
comparison. Syscalls which have the same effect (loosely) should have the
same canonical form and compare and hash as equal when canonicialized.

Function signatures and high level documentation in this module come from
http://man7.org/linux/man-pages/man2/syscalls.2.html.

Each ``_process_<name>`` method defined in this module is expected to take a
syscall with a matching name and return a canonicalized version of that
syscall. Conversion methods are exposed via ``canonicalize``.
"""


# Imports
from contextlib import contextmanager
from pathlib import Path
from typing import Any, List, Union

from lib import logger
from lib.strace.classes import (
    Collection,
    FunctionCall,
    Literal,
    LiteralValue,
    NullLiteral,
    SyntheticValue,
    Syscall,
)
from lib.strace.comparison import flags
from lib.strace.comparison.util import get_full_path


class CanonicalForm:
    """A standardized syscall."""

    def __init__(self, name: str, arguments: List[Any]):
        """Initialize a syscall canonical form.

        Parameters
        ----------
        name : str
            Syscall name.
        arguments : List[Any]
            Standardized arguments list.
        """
        self.tuple = (name, *arguments)

    def __hash__(self) -> int:
        """Hash a syscall canonical form.

        Returns
        -------
        int
            Canonical form hash.
        """
        return hash(self.tuple)

    def __eq__(self, other) -> bool:
        """Determine equality between self and another object.

        Parameters
        ----------
        other : Any
            Object to compare with.

        Returns
        -------
        bool
            True if other is an equivalent syscall canonical form.
        """
        if not isinstance(other, CanonicalForm):
            return NotImplemented
        return self.tuple == other.tuple

    def __repr__(self) -> str:
        """Create a string representation.

        Returns
        -------
        str
            String representation.
        """
        return f'<{CanonicalForm.__name__} {self.tuple}>'

    def __str__(self) -> str:
        """Create a string representation.

        Returns
        -------
        str
            String representation.
        """
        return self.__repr__()


def _get_value(v: Union[Literal, LiteralValue]) -> Any:
    """Get a native (or almost) native representation of the argument value.

    Parameters
    ----------
    v : Literal
        Valued argument.

    Returns
    -------
    Any
        Bare argument value.
    """
    # Process literal with optional identifier
    if isinstance(v, Literal):
        if v.identifier:
            return v.identifier.value, _get_value(v.value)
        else:
            return _get_value(v.value)

    # At this point we expect v to be an instance of LiteralValue.

    # If it's a collection, get the value for all items
    if isinstance(v, Collection):
        return tuple(map(_get_value, v.items))

    # If it's a function call, get the identifier and values of arguments
    if isinstance(v, FunctionCall):
        return v.identifier, *map(_get_value, v.arguments)

    # Other values should have a value attribute
    return v.value


def _has_synthetic_value(v: Literal) -> bool:
    """Determine if a literal contains a synthetic value.

    Parameters
    ----------
    v : Literal
        Literal to check for synthetic values.

    Returns
    -------
    bool
        True if v contains a synthetic value.
    """
    # Get the literal value
    value = v.value

    # Return true if the value is a synthetic value.
    if isinstance(value, SyntheticValue):
        return True

    # If value is a collection, return true if any item has a synthetic value
    if isinstance(value, Collection):
        return any(map(_has_synthetic_value, value.items))

    # If value is a function call, return true if any argument has a
    # synthetic value.
    if isinstance(value, FunctionCall):
        return any(map(_has_synthetic_value, value.arguments))

    # Otherwise, return false. Synthetic value replacement happens directly at
    # the literal level, so no other class can contain a synthetic value
    # (no other literal value contains other literals).
    return False


def _is_null(v: Literal) -> bool:
    """Check to see if a literal value is NULL.

    Parameters
    ----------
    v : Literal
        Literal to check.

    Returns
    -------
    bool
        True iff the literal value is a null literal.
    """
    return isinstance(v.value, NullLiteral)


def _default_process_syscall(s: Syscall) -> CanonicalForm:
    """Convert a syscall to a canonical form.

    This function is a default for converting any syscall if an explicit
    conversion function has not been defined.

    Parameters
    ----------
    s : Syscall
        Syscall to canonicalize.

    Returns
    -------
    CanonicalForm
        Canonicialized version.
    """
    return CanonicalForm(
        s.name,
        list(map(
            _get_value,
            filter(lambda a: isinstance(a, Literal), s.arguments)
        ))
    )


def canonicalize(s: Syscall) -> CanonicalForm:
    """Canonicalize a syscall.

    This function delegates to a specific process implementation for the passed
    syscall, or a default if no specific implementation is available.

    Parameters
    ----------
    s : Syscall
        Syscall to canonicalize.

    Returns
    -------
    CanonicalForm
        Canonicalized version.
    """
    try:
        return globals().get(f'_process_{s.name}', _default_process_syscall)(s)
    except Exception:
        logger.exception(
            f'Exception while attempting to canonicalize the syscall: \n{s}'
        )
        raise


@contextmanager
def canonical_repr():
    """Canonical representation context manager.

    When activated, the Syscall ``repr`` appears as the canonical form.
    """
    # Define new repr method.
    def __repr__(self: Syscall) -> str:
        return repr(canonicalize(self))

    # Save and replace old repr method.
    old_repr = Syscall.__repr__
    Syscall.__repr__ = __repr__

    # Yield and restore.
    try:
        yield
    finally:
        Syscall.__repr__ = old_repr


# Individual processing functions defined below.
#
# Functions are grouped by syscalls that share the same canonical form (ex.
# access and faccessat). In general, if a syscall's canonical form should be
# the same as the default, an alias will be made to _default_process_syscall.
# Syscalls that do not have a process function or alias defined have not been
# evaluated for canonical form.


# access, faccessat - check user's permissions for a file
# http://man7.org/linux/man-pages/man2/access.2.html
#
# Signature: int access(const char *pathname, int mode);
# Example:   access("/var/log/faillog", 0) = 0
#
# Signature: int faccessat(int dirfd, const char *pathname, int mode,
#                          int flags);
# Example:   faccessat(-100, "/usr/bin/gpgv", 0x1) = 0


_process_access = _default_process_syscall


def _process_faccessat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('access', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        _get_value(s.arguments[2])
    ])


# alarm - set an alarm clock for delivery of a signal
# http://man7.org/linux/man-pages/man2/alarm.2.html
#
# Signature: unsigned int alarm(unsigned int seconds);
# Example:   alarm(15) = 0


_process_alarm = _default_process_syscall


# arch_prctl - set architecture-specific thread state
# http://man7.org/linux/man-pages/man2/arch_prctl.2.html
#
# Signature: int arch_prctl(int code, unsigned long addr);
#            int arch_prctl(int code, unsigned long *addr);
# Example:   arch_prctl(0x1002, 0x7f0ad5a1c0c0) = 0


def _process_arch_prctl(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


# brk, sbrk - change data segment size
# http://man7.org/linux/man-pages/man2/brk.2.html
#
# Signature: int brk(void *addr);
# Example:   brk(0x559cadc2d000) = 0x559cadc2d000
#
# Signature: void *sbrk(intptr_t increment);


def _process_brk(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


def _process_sbrk(s: Syscall) -> CanonicalForm:
    return CanonicalForm('brk', [])


# chdir, fchdir - change working directory
# http://man7.org/linux/man-pages/man2/chdir.2.html
#
# Signature: int chdir(const char *path);
# Example:   chdir("/traces") = 0
#
# Signature: int fchdir(int fd);
# Example:   fchdir(4) = 0


_process_chdir = _default_process_syscall


def _process_fchdir(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chdir', [_get_value(s.arguments[0])])


# chmod, fchmod, fchmodat - change permissions of a file
# http://man7.org/linux/man-pages/man2/chmod.2.html
#
# Signature: int chmod(const char *pathname, mode_t mode);
# Example: chmod("/home/ansible-username-01", 0755) = 0
#
# Signature: int fchmod(int fd, mode_t mode);
# Example:   fchmod(13, 0644) = 0
#
# Signature: int fchmodat(int dirfd, const char *pathname, mode_t mode,
#                         int flags);
# Example:   fchmodat(-100, "/tmp/apt-key-gpghome.8Lg6DsT6Og", 0700) = 0


_process_chmod = _default_process_syscall


def _process_fchmod(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chmod', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ])


def _process_fchmodat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chmod', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        _get_value(s.arguments[2])
    ])


# chown, fchown, lchown, fchownat - change ownership of a file
# http://man7.org/linux/man-pages/man2/chown.2.html
#
# Signature: int chown(const char *pathname, uid_t owner, gid_t group);
# Example:   chown("/home/ansible-username-01", 1000, 1000) = 0
#
# Signature: int fchown(int fd, uid_t owner, gid_t group);
# Example:   fchown(13, 1000, 1000) = 0
#
# Signature: int lchown(const char *pathname, uid_t owner, gid_t group);
# Example:   lchown(0x55e36891a330, 100, 0) = 0
#
# Signature: int fchownat(int dirfd, const char *pathname, uid_t owner,
#                         gid_t group, int flags);
# Example:   fchownat(-100, ".", 0, 0, 0) = 0


_process_chown = _default_process_syscall


def _process_chown32(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chown', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
    ])


def _process_fchown(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chown', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
    ])


_process_fchown32 = _process_fchown


def _process_lchown(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chown', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
    ])


_process_lchown32 = _process_lchown


def _process_fchownat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('chown', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3]),
        _get_value(s.arguments[4]),
    ])


# clock_getres, clock_gettime, clock_settime - clock and time functions
# http://man7.org/linux/man-pages/man2/clock_gettime.2.html
#
# Signature: int clock_getres(clockid_t clk_id, struct timespec *res);
#
# Signature: int clock_gettime(clockid_t clk_id, struct timespec *tp);
# Example:
#
# Signature: int clock_settime(clockid_t clk_id, const struct timespec *tp);


def _process_clock_getres(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_clock_gettime(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_clock_settime(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


# clone, __clone2, clone3 - create a child process
# http://man7.org/linux/man-pages/man2/clone.2.html
#
# Note, Strace appears to obliterate the clone signature when reporting it.
# Not making a determination for __clone2 and clone3 until we have an example
# of each call and how Strace will report them.
#
# Signature: long clone(unsigned long flags, void *stack, int *parent_tid,
#                       int *child_tid, unsigned long tls);
# Example:   clone(child_stack=NULL, flags=0x1200000|17,
#                  child_tidptr=0x7fdcd0ec7a10) = 69


def _process_clone(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ])


# close - close a file descriptor
# http://man7.org/linux/man-pages/man2/close.2.html
#
# Signature: int close(int fd);
# Example:   close(0) = 0


_process_close = _default_process_syscall


# connect - initiate a connection on a socket
# http://man7.org/linux/man-pages/man2/connect.2.html
#
# Signature: int connect(int sockfd, const struct sockaddr *addr,
#                        socklen_t addrlen);
# Example:   connect(11, {sa_family=0x1, sun_path="/dev/log"}, 110) = -1


_process_connect = _default_process_syscall


# dup, dup2, dup3 - duplicate a file descriptor
# http://man7.org/linux/man-pages/man2/dup.2.html
#
# Signature: int dup(int oldfd);
# Example:   dup(0) = 3
#
# Signature: int dup2(int oldfd, int newfd);
# Example:   dup2(3, 0) = 0
#
# Signature: int dup3(int oldfd, int newfd, int flags);


_process_dup = _default_process_syscall


def _process_dup2(s: Syscall) -> CanonicalForm:
    return CanonicalForm('dup', [_get_value(s.arguments[0])])


def _process_dup3(s: Syscall) -> CanonicalForm:
    return CanonicalForm('dup', [_get_value(s.arguments[0])])


# execve, execveat - execute program
# http://man7.org/linux/man-pages/man2/execve.2.html
# http://man7.org/linux/man-pages/man2/execveat.2.html
#
# Signature: int execve(const char *pathname, char *const argv[],
#                       char *const envp[]);
# Example:   execve("/bin/rm", ["rm", "-rf", "linux-filename-02"],
#                   0x7fff26ebba98 /* 13 vars */) = 0
#
# Signature: int execveat(int dirfd, const char *pathname, char *const argv[],
#                         char *const envp[], int flags);


def _process_execve(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        Path(_get_value(s.arguments[0])).name,
        _get_value(s.arguments[1])[1:],
    ])


def _process_execveat(s: Syscall) -> CanonicalForm:
    path = Path(get_full_path(
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ))
    return CanonicalForm('execve', [
        path.name,
        _get_value(s.arguments[2])[1:]
    ])


# _exit, _Exit. exit_group - terminate the calling process
# http://man7.org/linux/man-pages/man2/exit.2.htmlhttp://man7.org/linux/man-pages/man2/exit.2.html
# http://man7.org/linux/man-pages/man2/exit_group.2.html
#
# Signature: void _exit(int status);
# Example:   exit(0) = ?
#
# Signature: void exit_group(int status);
# Example:   exit_group(0) = ?


_process_exit = _default_process_syscall


_process_Exit = _default_process_syscall


_process_exit_group = _default_process_syscall


# fcntl - manipulate file descriptor
# http://man7.org/linux/man-pages/man2/fcntl.2.html
#
# Signature: int fcntl(int fd, int cmd, ... /* arg */ );
# Example:   fcntl(3, 0x1) = 0x1
# Example:   fcntl(5, 0x2, 0x1) = 0
# Example:   fcntl(5, 0x3) = 0x28802
# Example:   fcntl(4, 0x7, {l_type=0x1, l_whence=0, l_start=0, l_len=0}) = 0


def _process_fcntl(s: Syscall) -> CanonicalForm:
    # Get fcntl command
    cmd = _get_value(s.arguments[1])

    # If the command is one of the locking commands, it takes a struct * as the
    # third argument. We care that the lock is being requested on the file, and
    # what type of lock it is, but not the other information (l_whence, etc.).
    if cmd in (flags.F_SETLK, flags.F_SETLKW, flags.F_GETLK,
               flags.F_SETLK64, flags.F_SETLKW64, flags.F_GETLK64,
               flags.F_OFD_SETLK, flags.F_OFD_SETLKW, flags.F_OFD_GETLK):
        return CanonicalForm('fcntl', [
            _get_value(s.arguments[0]),
            _get_value(s.arguments[1]),
            _get_value(s.arguments[2])[0]
        ])

    # If the command is F_GETOWN_EX, the third argument is a struct * for the
    # return value that is dependent on the environment. Note that F_SETOWN_EX
    # also passes a struct * as the third argument, but it provides input for
    # the function behavior.
    if cmd in (flags.F_GETOWN_EX,):
        return CanonicalForm('fcntl', [
            _get_value(s.arguments[0]),
            _get_value(s.arguments[1]),
        ])

    # All other commands have either 2 or 3 arguments. If there is a third,
    # argument, it is either a primitive or a struct, but is not used for
    # a return value.
    return CanonicalForm('fcntl', list(map(_get_value, s.arguments)))


_process_fcntl64 = _process_fcntl


# fsync,  fdatasync  -  synchronize a file's in-core state with storage device
# http://man7.org/linux/man-pages/man2/fsync.2.html
#
# Signature: int fsync(int fd);
# Example: fsync(11) = 0
#
# Signature: int fdatasync(int fd);
# Example: fdatasync(3) = 0


_process_fsync = _default_process_syscall


_process_fdatasync = _default_process_syscall


# futex - fast user-space locking
# http://man7.org/linux/man-pages/man2/futex.2.html
#
# Signature: int futex(int *uaddr, int futex_op, int val,
#                      const struct timespec *timeout, int *uaddr2, int val3);
# Example: futex(0x7fdcd12190c8, 0x81, 2147483647) = 0


def _process_futex(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2])
    ])


# get_robust_list, set_robust_list - get/set list of robust futexes
# http://man7.org/linux/man-pages/man2/set_robust_list.2.html
#
# Signature: long get_robust_list(int pid, struct robust_list_head **head_ptr,
#                                 size_t *len_ptr);
#
# Signature: long set_robust_list(struct robust_list_head *head, size_t len);
# Example:   set_robust_list(0x7f7b7497aa20, 24) = 0


def _process_get_robust_list(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


def _process_set_robust_list(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[1])])


# getcwd, getwd, get_current_dir_name - get current working directory
# http://man7.org/linux/man-pages/man2/getcwd.2.html
#
# Signature: char *getcwd(char *buf, size_t size);
# Example:   getcwd("/traces", 4096) = 8
#
# Signature: char *getwd(char *buf);
#
# Signature: char *get_current_dir_name(void);


def _process_getcwd(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


def _process_getwd(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getcwd', [])


def _process_get_current_dir_name(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getcwd', [])


# getdents, getdents64 - get directory entries
# http://man7.org/linux/man-pages/man2/getdents.2.html
#
# Signature: int getdents(unsigned int fd, struct linux_dirent *dirp,
#                         unsigned int count);
#
# Signature: int getdents64(unsigned int fd, struct linux_dirent64 *dirp,
#                           unsigned int count);
# Example:   getdents64(3, /* 9 entries */, 280) = 216


def _process_getdents(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_getdents64(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getdents', [_get_value(s.arguments[0])])


# getgid, getegid - get group identity
# http://man7.org/linux/man-pages/man2/getgid.2.html
#
# Structure: gid_t getgid(void);
# Example:   getgid() = 0
#
# Structure: gid_t getegid(void);
# Example:   getegid() = 0


_process_getgid = _default_process_syscall


def _process_getgid32(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getgid', [])


def _process_getegid(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getgid', [])


_process_getegid32 = _process_getegid


# getuid, geteuid - get user identity
# http://man7.org/linux/man-pages/man2/geteuid.2.html
#
# Structure: uid_t getuid(void);
# Example:   getuid() = 0
#
# Structure: uid_t geteuid(void);
# Example:   getegid() = 0


_process_getuid = _default_process_syscall


def _process_getuid32(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getuid', [])


def _process_geteuid(s: Syscall) -> CanonicalForm:
    return CanonicalForm('getuid', [])


_process_geteuid32 = _process_geteuid


# getpid, getppid - get process identification
# http://man7.org/linux/man-pages/man2/getpid.2.html
#
# Signature: pid_t getpid(void);
# Example:   getpid() = 69
#
# Signature: pid_t getppid(void);
# Example:   getppid() = 98


_process_getpid = _default_process_syscall


_process_getppid = _default_process_syscall


# getrandom - obtain a series of random bytes
# http://man7.org/linux/man-pages/man2/getrandom.2.html
#
# Signature: ssize_t getrandom(void *buf, size_t buflen, unsigned int flags);
# Example:   getrandom("\xb6\x34\x1b\xb0\x2d\"..., 24, 0x1) = 24


def _process_getrandom(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2])
    ])


# getrlimit, setrlimit, prlimit - get/set resource limits
# http://man7.org/linux/man-pages/man2/prlimit64.2.html
#
# Signature: int getrlimit(int resource, struct rlimit *rlim);
#
# Signature: int setrlimit(int resource, const struct rlimit *rlim);
#
# Signature: int prlimit(pid_t pid, int resource,
#                        const struct rlimit *new_limit,
#                        struct rlimit *old_limit);
# Example:   prlimit64(0, 0x3, NULL,
#                      {rlim_cur=8192*1024, rlim_max=RLIM64_INFINITY}) = 0


def _process_getrlimit(s: Syscall) -> CanonicalForm:
    return CanonicalForm('rlimit', [
        _get_value(s.arguments[0]),
        'NULL',
        True
    ])


def _process_setrlimit(s: Syscall) -> CanonicalForm:
    return CanonicalForm('rlimit', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        False
    ])


def _process_prlimit(s: Syscall) -> CanonicalForm:
    return CanonicalForm('rlimit', [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        isinstance(s.arguments[3].value, Collection)
    ])


# gettid - get thread identification
# http://man7.org/linux/man-pages/man2/gettid.2.html
#
# Signature: pid_t gettid(void);
# Example: gettid() = 468

_process_gettid = _default_process_syscall


# ioctl - control device
# http://man7.org/linux/man-pages/man2/ioctl.2.html
#
# Signature: int ioctl(int fd, unsigned long request, ...);
# Example: ioctl(0, 0x5401, {0xf opost isig icanon echo ...}) = 0


def _process_ioctl(s: Syscall) -> CanonicalForm:
    # The third argument is a pointer that serves dual purpose as an in or out
    # parameter depending on the request. The semantics of ioctl vary based on
    # the device driver in use, so there's no great way to tell which. For now,
    # canonicalize only on interaction with some device and the request sent.
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
    ])


# link, linkat - make a new name for a file
# http://man7.org/linux/man-pages/man2/link.2.html
#
# Signature: int link(const char *oldpath, const char *newpath);
# Example:   link("/etc/passwd.69", "/etc/passwd.lock") = 0
#
# Signature: int linkat(int olddirfd, const char *oldpath, int newdirfd,
#                       const char *newpath, int flags);


_process_link = _default_process_syscall


def _process_linkat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('link', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        get_full_path(_get_value(s.arguments[2]), _get_value(s.arguments[3]))
    ])


# lseek - reposition read/write file offset
# http://man7.org/linux/man-pages/man2/lseek.2.html
#
# Signature: off_t lseek(int fd, off_t offset, int whence);


def _process_lseek(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


# mkdir, mkdirat - create a directory
# http://man7.org/linux/man-pages/man2/mkdir.2.html
#
# Signature: int mkdir(const char *pathname, mode_t mode);
# Example:   mkdir("/home/ansible-username-01", 000) = 0
#
# Signature: int mkdirat(int dirfd, const char *pathname, mode_t mode);
# Example:   mkdirat(-100, ".", 0700) = -1


_process_mkdir = _default_process_syscall


def _process_mkdirat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('mkdir', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        _get_value(s.arguments[2])
    ])


# mmap, mmap2, munmap - map or unmap files or devices into memory
# http://man7.org/linux/man-pages/man2/mmap.2.html
# http://man7.org/linux/man-pages/man2/mmap2.2.html
#
# Signature: void *mmap(void *addr, size_t length, int prot, int flags,
#                       int fd, off_t offset);
# Example:   mmap(NULL, 8141, 0x1, 0x2, 3, 0)  = 0x7f0ad5c29000
#
# Signature: void *mmap2(void *addr, size_t length, int prot, int flags,
#                        int fd, off_t pgoffset);
#
# Signature: int munmap(void *addr, size_t length);
# Example:   munmap(0x7f0ad5c29000, 8141) = 0


def _process_mmap(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3]),
        _get_value(s.arguments[4])
    ])


def _process_mmap2(s: Syscall) -> CanonicalForm:
    return CanonicalForm('mmap', [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3]),
        _get_value(s.arguments[4])
    ])


def _process_munmap(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [s.arguments[1].value.value])


# mprotect, pkey_mprotect - set protection on a region of memory
# http://man7.org/linux/man-pages/man2/mprotect.2.html
#
# Signature: int mprotect(void *addr, size_t len, int prot);
# Example:   mprotect(0x7f0ad5a09000, 40960, 0) = 0
#
# Signature: int pkey_mprotect(void *addr, size_t len, int prot, int pkey);


def _process_mprotect(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2])
    ])


def _process_pkey_mprotect(s: Syscall) -> CanonicalForm:
    return CanonicalForm('mprotect', [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2])
    ])


# open, openat, creat - open and possibly create a file
# http://man7.org/linux/man-pages/man2/open.2.html
#
# Signature: int open(const char *pathname, int flags);
# Signature: int open(const char *pathname, int flags, mode_t mode);
#
# Signature: int creat(const char *pathname, mode_t mode);
#
# Signature: int openat(int dirfd, const char *pathname, int flags);
# Signature: int openat(int dirfd, const char *pathname, int flags,
#                       mode_t mode);
# Example:   openat(-100, "/etc/ld.so.cache", 0x80000) = 3


def _process_open(s: Syscall) -> CanonicalForm:
    # The mode is required when opening with the flags O_CREATE or O_TMPFILE.
    # Check flags for equality because TMPFILE is composed of multiple values.
    f = _get_value(s.arguments[1])
    create = f & flags.O_CREAT == flags.O_CREAT
    tmpfile = f & flags.O_TMPFILE == flags.O_TMPFILE
    if create or tmpfile:
        return CanonicalForm(s.name, [
            _get_value(s.arguments[0]),
            _get_value(s.arguments[2])
        ])
    else:
        return CanonicalForm(s.name, [
            _get_value(s.arguments[0]),
        ])


def _process_creat(s: Syscall) -> CanonicalForm:
    # flags.O_WRONLY | flags.O_CREAT | flags.O_TRUNC,
    return CanonicalForm('open', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ])


def _process_openat(s: Syscall) -> CanonicalForm:
    # The mode is required when opening with the flags O_CREATE or O_TMPFILE.
    # Check flags for equality because TMPFILE is composed of multiple values.
    arg2 = s.arguments[2].value
    if isinstance(arg2, SyntheticValue):
        f = _get_value(arg2.original_value)
    else:
        f = _get_value(arg2)
    create = f & flags.O_CREAT == flags.O_CREAT
    tmpfile = f & flags.O_TMPFILE == flags.O_TMPFILE
    if create or tmpfile:
        return CanonicalForm('open', [
            get_full_path(
                _get_value(s.arguments[0]), _get_value(s.arguments[1])
            ),
            _get_value(s.arguments[3])
        ])
    else:
        return CanonicalForm('open', [
            get_full_path(
                _get_value(s.arguments[0]), _get_value(s.arguments[1])
            ),
        ])


# pipe, pipe2 - create pipe
# http://man7.org/linux/man-pages/man2/pipe2.2.html
#
# Signature: int pipe(int pipefd[2]);
#
# Signature: int pipe2(int pipefd[2], int flags);
# Example:   pipe2([3, 4], 0x80000) = 0


def _process_pipe(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


def _process_pipe2(s: Syscall) -> CanonicalForm:
    return CanonicalForm('pipe', [])


# poll, ppoll - wait for some event on a file descriptor
# http://man7.org/linux/man-pages/man2/poll.2.html
#
# Signature: int poll(struct pollfd *fds, nfds_t nfds, int timeout);
# Example:   poll([{fd=3, events=0x1}], 1, 500) = 1 ([{fd=3, revents=0x1}])
#
# Signature: int ppoll(struct pollfd *fds, nfds_t nfds,
#                      const struct timespec *tmo_p, const sigset_t *sigmask);


def _process_poll(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2])
    ])


def _process_ppole(s: Syscall) -> CanonicalForm:
    timespec = _get_value(s.arguments[3])
    return CanonicalForm('pole', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        int(timespec[0][1] * 1000 + timespec[1][1] / 1000000)
    ])


# read - read from a file descriptor
# http://man7.org/linux/man-pages/man2/read.2.html
#
# Signature: ssize_t read(int fd, void *buf, size_t count);
# Example:   read(12, "# ~/.bash_logout: executed by ba"..., 1024) = 220


def _process_read(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[2])
    ])


# readlink, readlinkat - read value of a symbolic link
# http://man7.org/linux/man-pages/man2/readlink.2.html
#
# Signature: ssize_t readlink(const char *pathname, char *buf, size_t bufsiz);
#
# Signature: ssize_t readlinkat(int dirfd, const char *pathname, char *buf,
#                               size_t bufsiz);


def _process_readlink(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[2])
    ])


def _process_readlinkat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('readlink', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        _get_value(s.arguments[3])
    ])


# recv, recvfrom, recvmsg - receive a message from a socket
# http://man7.org/linux/man-pages/man2/recvfrom.2.html
#
# Signature: ssize_t recv(int sockfd, void *buf, size_t len, int flags);
#
# Signature: ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
#                             struct sockaddr *src_addr, socklen_t *addrlen);
# Example:   recvfrom(3, {{len=36, type=0x2, flags=0, seq=1, pid=321},
#                     {error=0, msg={len=116, type=0x45c, flags=0x5, seq=1,
#                     pid=0}}}, 8988, 0x40, {sa_family=0x10, nl_pid=0,
#                     nl_groups=00000000}, [12]) = 36
#
# Signature: ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);
# Example:   recvmsg(3, 0x7ffde01adda0, 0) = 164


def _process_recv(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_recvfrom(s: Syscall) -> CanonicalForm:
    return CanonicalForm('recv', [_get_value(s.arguments[0])])


def _process_recvmsg(s: Syscall) -> CanonicalForm:
    return CanonicalForm('recv', [_get_value(s.arguments[0])])


# rename, renameat, renameat2 - change the name or location of a file
# http://man7.org/linux/man-pages/man2/rename.2.html
#
# Signature: int rename(const char *oldpath, const char *newpath);
# Example:   rename("/etc/passwd+", "/etc/passwd") = 0
#
# Signature: int renameat(int olddirfd, const char *oldpath,
#                         int newdirfd, const char *newpath);
#
# Signature: int renameat2(int olddirfd, const char *oldpath,
#                          int newdirfd, const char *newpath,
#                          unsigned int flags);


_process_rename = _default_process_syscall


def _process_renameat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('rename', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1])),
        get_full_path(_get_value(s.arguments[2]), _get_value(s.arguments[3]))
    ])


_process_renameat2 = _process_renameat


# sigaction, rt_sigaction - examine and change a signal action
# http://man7.org/linux/man-pages/man2/rt_sigaction.2.html
#
# Signature: int sigaction(int signum, const struct sigaction *act,
#                          struct sigaction *oldact);
#
# Signature: int sigaction(int signum, const struct sigaction *act,
#                          struct sigaction *oldact, size_t sigsetsize);
# Example:   rt_sigaction(32, {sa_handler=0x7f9537c676b0, sa_mask=[],
#                         sa_flags=0x4000004, sa_restorer=0x7f9537c73730},
#                         NULL, 8) = 0


def _process_rt_sigaction(s: Syscall) -> CanonicalForm:
    canonical_act = _get_value(s.arguments[1])
    if isinstance(canonical_act, tuple):
        canonical_act = canonical_act[1:3]

    canonical_oldact = _get_value(s.arguments[2])
    if isinstance(canonical_oldact, tuple):
        canonical_oldact = True

    return CanonicalForm('sigaction', [
        _get_value(s.arguments[0]),
        canonical_act,
        canonical_oldact
    ])


_process_sigaction = _process_rt_sigaction


# sigprocmask, rt_sigprocmask - examine and change blocked signals
# http://man7.org/linux/man-pages/man2/rt_sigprocmask.2.html
#
# Signature: int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);
#
# Signature: int rt_sigprocmask(int how, const kernel_sigset_t *set,
#                               kernel_sigset_t *oldset, size_t sigsetsize);
# Example:   rt_sigprocmask(0x1, [RTMIN RT_1], NULL, 8) = 0


def _process_rt_sigprocmask(s: Syscall) -> CanonicalForm:
    return CanonicalForm('sigprocmask', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1]),
        isinstance(s.arguments[2].value, Collection)
    ])


_process_sigprocmask = _process_rt_sigprocmask


# select, pselect - synchronous I/O multiplexing
# http://man7.org/linux/man-pages/man2/select.2.html
#
# Signature: int select(int nfds, fd_set *readfds, fd_set *writefds,
#                       fd_set *exceptfds, struct timeval *timeout);
# Example:   select(6, [3 5], [], [3 5], {tv_sec=1, tv_usec=0})
#                   = 2 (in [3 5], left {tv_sec=0, tv_usec=999983})
#
# Signature: int pselect(int nfds, fd_set *readfds, fd_set *writefds,
#                        fd_set *exceptfds, const struct timespec *timeout,
#                        const sigset_t *sigmask);


def _process_select(s: Syscall) -> CanonicalForm:
    timeout = _get_value(s.arguments[4])
    if timeout == 'NULL':
        time = None
    else:
        time = timeout[0][1] + (timeout[1][1] * 10**6)
    return CanonicalForm(s.name, [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3]),
        time
    ])


def _process_pselect(s: Syscall) -> CanonicalForm:
    timeout = _get_value(s.arguments[4])
    if timeout == 'NULL':
        time = None
    else:
        time = timeout[0][1] + (timeout[1][1] * 10**9)
    return CanonicalForm('select', [
        _get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3]),
        time
    ])


# send, sendto, sendmsg - send a message on a socket
# http://man7.org/linux/man-pages/man2/sendto.2.html
#
# Signature: ssize_t send(int sockfd, const void *buf, size_t len, int flags);
#
# Signature: ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
#                           const struct sockaddr *dest_addr,
#                           socklen_t addrlen);
# Example:   sendto(3, {{len=132, type=0x45c, flags=0x5, seq=1, pid=0},
#                   "\x6f\x70\"...}, 132, 0,
#                   {sa_family=0x10, nl_pid=0, nl_groups=00000000}, 12) = 132
#
# Signature: ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);


def _process_send(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        *_get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3])
    ])


def _process_sendto(s: Syscall) -> CanonicalForm:
    return CanonicalForm('send', [
        _get_value(s.arguments[0]),
        *_get_value(s.arguments[1]),
        _get_value(s.arguments[2]),
        _get_value(s.arguments[3])
    ])


# set_tid_address - set pointer to thread ID
# http://man7.org/linux/man-pages/man2/set_tid_address.2.html
#
# Signature: long set_tid_address(int *tidptr);
# Example:   set_tid_address(0x7f207fa4aa10) = 504


def _process_set_tid_address(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


# sigaltstack - set and/or get signal stack context
# http://man7.org/linux/man-pages/man2/sigaltstack.2.html
#
# Signature: int sigaltstack(const stack_t *ss, stack_t *old_ss);
# Example:   sigaltstack({ss_sp=0x557f7f36cbd0, ss_flags=0, ss_size=16384},
#                        {ss_sp=NULL, ss_flags=0x2, ss_size=0}) = 0


def _process_sigaltstack(s: Syscall) -> CanonicalForm:
    ss = _get_value(s.arguments[0])
    if isinstance(ss, tuple):
        ss = ss[1:]

    return CanonicalForm(s.name, [
        ss,
        isinstance(s.arguments[1].value, Collection)
    ])


# socket - create an endpoint for communication
# http://man7.org/linux/man-pages/man2/socket.2.html
#
# Signature: int socket(int domain, int type, int protocol);
# Example:   socket(0x1, 0x1|0x80800, 0) = 4


_process_socket = _default_process_syscall


# stat, fstat, lstat, fstatat, fstatat64, newfstatat - get file status
# http://man7.org/linux/man-pages/man2/stat.2.html
#
# Signature: int stat(const char *pathname, struct stat *statbuf);
# Example: stat("/usr/lib/python2.7/os.py",
#               {st_mode=0100644, st_size=25910, ...}) = 0
#
# Signature: int fstat(int fd, struct stat *statbuf);
# Example:   fstat(3, {st_mode=0100644, st_size=35807, ...}) = 0
#
# Signature: int lstat(const char *pathname, struct stat *statbuf);
# Example:   lstat("/dev/pts/0", {st_mode=020620, st_rdev=0x8800, ...}) = 0
#
# Signature: int fstatat(int dirfd, const char *pathname, struct stat *statbuf,
#                        int flags);
# Example:   newfstatat(-100, "/tmp/test",
#                       {st_mode=0100644, st_size=0, ...}, 0x100) = 0

def _process_stat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('stat', [_get_value(s.arguments[0])])


_process_stat64 = _process_stat


def _process_fstat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('stat', [_get_value(s.arguments[0])])


_process_fstat64 = _process_fstat


def _process_lstat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('stat', [_get_value(s.arguments[0])])


_process_lstat64 = _process_lstat


def _process_newfstatat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('stat', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1]))
    ])


_process_fstatat = _process_newfstatat


_process_fstatat64 = _process_newfstatat


# statfs, fstatfs - get filesystem statistics
# http://man7.org/linux/man-pages/man2/statfs.2.html
#
# Signature: int statfs(const char *path, struct statfs *buf);
# Example:   statfs("/sys/fs/selinux", 0x7ffca4665da0) = -1
#
# Signature: int fstatfs(int fd, struct statfs *buf);


def _process_statfs(s: Syscall) -> CanonicalForm:
    return CanonicalForm('statfs', [_get_value(s.arguments[0])])


_process_statfs64 = _process_statfs


def _process_fstatfs(s: Syscall) -> CanonicalForm:
    return CanonicalForm('statfs', [_get_value(s.arguments[0])])


_process_fstatfs64 = _process_fstatfs


# sysinfo - return system information
# http://man7.org/linux/man-pages/man2/sysinfo.2.html
#
# Signature: int sysinfo(struct sysinfo *info);
# Example:   sysinfo({uptime=533107, loads=[42176, 13600, 4384],
#                     totalram=8360480768, freeram=6802702336,
#                     sharedram=864256, bufferram=269873152,
#                     totalswap=1073737728, freeswap=1073737728,
#                     procs=534, totalhigh=0, freehigh=0, mem_unit=1}) = 0


def _process_sysinfo(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


# umask - set file mode creation mask
# http://man7.org/linux/man-pages/man2/umask.2.html
#
# Signature: mode_t umask(mode_t mask);
# Example:   umask(0777) = 022


_process_umask = _default_process_syscall


# uname - get name and information about current kernel
# http://man7.org/linux/man-pages/man2/uname.2.html
#
# Signature: int uname(struct utsname *buf);
# Example:   uname({sysname="Linux", nodename="3395ae0e36e3", ...}) = 0


def _process_uname(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [])


# unlink, unlinkat - delete a name and possibly the file it refers to
# http://man7.org/linux/man-pages/man2/unlink.2.html
#
# Signature: int unlink(const char *pathname);
# Example:   unlink("/etc/passwd.469") = 0
#
# Signature: int unlinkat(int dirfd, const char *pathname, int flags);
# Example:   unlinkat(5, "gpg.1.sh", 0) = 0


def _process_unlink(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_unlinkat(s: Syscall) -> CanonicalForm:
    dir_fd = _get_value(s.arguments[0])
    pathname = _get_value(s.arguments[1])
    s_flags = _get_value(s.arguments[2])
    path = get_full_path(dir_fd, pathname)
    if int(s_flags) & flags.AT_REMOVEDIR:
        return CanonicalForm('rmdir', [path])
    else:
        return CanonicalForm('unlink', [path])


# utime, utimes - change file last access and modification times
# http://man7.org/linux/man-pages/man2/utime.2.html
#
# utimensat, futimens  - change file timestamps with nanosecond precision
# http://man7.org/linux/man-pages/man2/utimensat.2.html
#
# Signature: int utime(const char *filename, const struct utimbuf *times);
# Example:   utime("/etc/passwd-", {actime=1575643648, modtime=1575643648}) = 0
#
# Signature: int utimes(const char *filename, const struct timeval times[2]);
# Example:   utimes("/usr/share/doc/libapt-inst2.0.dpkg-new",
#                   [{tv_sec=1578413479, tv_usec=0},
#                   {tv_sec=1559054429, tv_usec=0}) = 0
#
# Signature: int utimensat(int dirfd, const char *pathname,
#                          const struct timespec times[2], int flags);
# Example:   utimensat(5, NULL, [{tv_sec=1578413422, tv_nsec=306596000},
#                      {tv_sec=1578413423, tv_nsec=446596000}], 0) = 0
#
# Signature: int futimens(int fd, const struct timespec times[2]);


def _process_utime(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [_get_value(s.arguments[0])])


def _process_utimes(s: Syscall) -> CanonicalForm:
    return CanonicalForm('utime', [_get_value(s.arguments[0])])


def _process_utimensat(s: Syscall) -> CanonicalForm:
    return CanonicalForm('utimensat', [
        get_full_path(_get_value(s.arguments[0]), _get_value(s.arguments[1]))
    ])


def _process_futimens(s: Syscall) -> CanonicalForm:
    return CanonicalForm('utime', [_get_value(s.arguments[0])])


# wait, waitpid, waitid - wait for process to change state
# wait3, wait4 - wait for process to change state, BSD style
# http://man7.org/linux/man-pages/man2/waitpid.2.html
# http://man7.org/linux/man-pages/man2/wait4.2.html
#
# Signature: pid_t wait(int *wstatus);
#
# Signature: pid_t waitpid(pid_t pid, int *wstatus, int options);
#
# Signature: int waitid(idtype_t idtype, id_t id, siginfo_t *infop,
#                       int options, struct *rusage);
#
# Signature: pid_t wait3(int *wstatus, int options, struct rusage *rusage);
#
# Signature: pid_t wait4(pid_t pid, int *wstatus, int options,
#                        struct rusage *rusage);
# Example:   wait4(403, [{WIFEXITED(s) && WEXITSTATUS(s) == 127}], 0, NULL)
#                  = 403


def _process_wait(s: Syscall) -> CanonicalForm:
    return CanonicalForm('wait', [flags.P_ALL])


def _process_waitpid(s: Syscall) -> CanonicalForm:
    pid = _get_value(s.arguments[0])
    if pid < -1:
        return CanonicalForm('wait', [flags.P_PGID, -pid])
    elif pid == -1:
        return CanonicalForm('wait', [flags.P_ALL])
    elif pid == 0:
        return CanonicalForm('wait', [flags.P_PGID, 0])
    else:
        return CanonicalForm('wait', [flags.P_PID, pid])


def _process_waitid(s: Syscall) -> CanonicalForm:
    return CanonicalForm('wait', [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ])


def _process_wait3(s: Syscall) -> CanonicalForm:
    return CanonicalForm('wait', [flags.P_ALL])


def _process_wait4(s: Syscall) -> CanonicalForm:
    return CanonicalForm('wait', [flags.P_PID, _get_value(s.arguments[0])])


# write - write to a file descriptor
# http://man7.org/linux/man-pages/man2/write.2.html
#
# Signature: ssize_t write(int fd, const void *buf, size_t count);
# Example:   write(1, "test\n", 5) = 5


def _process_write(s: Syscall) -> CanonicalForm:
    return CanonicalForm(s.name, [
        _get_value(s.arguments[0]),
        _get_value(s.arguments[1])
    ])
