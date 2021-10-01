"""Comparison utils."""


# Imports
from typing import Tuple, Union
import os


from lib.strace.comparison import flags


def get_full_path(dir_fd: Union[int, str],
                  pathname: str) -> Union[str, Tuple[int, str]]:
    """Get a full path.

    This function is based on the usage of *at syscalls like openat and
    unlinkat, which accept an optional directory file descriptor.

    Parameters
    ----------
    dir_fd : Any
        The directory file descriptor. This may be a numeric flag, or an actual
        file descriptor. It may also have been replaced by a string for the
        directory path during preprocessing.
    pathname : str
        File pathname.

    Returns
    -------
    Union[str, Tuple[int, str]]
        Either a single pathname, or a tuple of directory file descriptor and
        pathname.
    """
    # Use pathname as the full pathname if:
    # - The pathname is absolute
    # - dir_fd is AT_FDCWD (relative to the current working directory)
    if os.path.isabs(pathname) or dir_fd == flags.AT_FDCWD:
        return pathname
    # If dir_fd is a string, it has been replaced with a path during
    # preprocessing.
    elif isinstance(dir_fd, str):
        # If pathname is null, use just the path at dir_fd as the full path.
        if pathname == 'NULL':
            return dir_fd
        # Join dir_fd and pathname to create a full path.
        else:
            return os.path.normpath(os.path.join(dir_fd, pathname))
    # Return a tuple of (dir_fd, pathname). We don't have enough information
    # about dir_fd to construct a full filesystem path.
    else:
        return dir_fd, pathname
