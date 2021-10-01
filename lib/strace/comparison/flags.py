"""Values used for linux flags."""


# uapi/asm-generic/fcntl.h
# https://elixir.bootlin.com/linux/latest/source/include/uapi/asm-generic/fcntl.h
AT_FDCWD = -100
AT_REMOVEDIR = 0x200
AT_SYMLINK_FOLLOW = 0x400

F_DUPFD = 0
F_DUPFD_CLOEXEC = 1030

F_GETLK = 5
F_SETLK = 6
F_SETLKW = 7

F_GETLK64 = 12
F_SETLK64 = 13
F_SETLKW64 = 14

F_SETOWN_EX = 15
F_GETOWN_EX = 16

F_OFD_GETLK = 36
F_OFD_SETLK = 37
F_OFD_SETLKW = 38

O_WRONLY = 0o1
O_CREAT = 0o100
O_TRUNC = 0o01000

O_DIRECTORY = 0o200000
__O_TMPFILE = 0o20000000
O_TMPFILE = __O_TMPFILE | O_DIRECTORY


# uapi/linux/sched.h
# https://elixir.bootlin.com/linux/v5.5.2/source/include/uapi/linux/sched.h
CLONE_FILES = 0o400


# uapi/asm/signal.h
# https://elixir.bootlin.com/linux/latest/source/arch/parisc/include/uapi/asm/signal.h
SIG_DFL = 0
SIG_IGN = 1


# uapi/linux/wait.h
# https://elixir.bootlin.com/linux/v5.5.2/source/include/uapi/linux/wait.h
P_ALL = 0
P_PID = 1
P_PGID = 2
P_PIDFD = 3
